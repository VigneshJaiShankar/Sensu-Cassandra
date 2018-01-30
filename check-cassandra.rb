#! /usr/bin/env ruby
#
# check-cassandra.rb [-i info_metric]  [-s info_sub_metric] [-w info_warn] [-c info_crit] [-t tp_metric] [-W tp_warn] [-C tp_crit] [-k cf_keyspace_name] [-m cf_keyspace_metric] [-T cf_table_name] [-M cf_table_metric] [-a cf_warn] [-b cf_crit]
#
# check-cassandra.rb -i heap_memory -s heap_used -w 200 -c 500 -t ReadStage -W 4 -C 5 -k system_schema -m read_count -T events -M sstable_count -a 20 -b 30

require 'sensu-plugin/check/cli'

 UNITS_FACTOR = {
    'bytes' => 1,
    'KB' => 1024,
    'KiB' => 1024,
    'MB' => 1024**2,
    'MiB' => 1024**2,
    'GB' => 1024**3,
    'GiB' => 1024**3,
    'TB' => 1024**4,
    'TiB' => 1024**4
  }.freeze

class CheckCassandra < Sensu::Plugin::Check::CLI

  option :info_metric,
         description: 'Info Metrics in cassandra',
         short: '-i INFO_METRIC',
         proc: proc { |a| a.to_s},
         required: true
 
  option :info_sub_metric,                                                               
         description: 'Sub categories of the info metrics',
         short: '-s INFO_SUB_METRIC',
         proc: proc { |a| a.to_s},
         required: if ARGV.include?("heap_memory") || ARGV.include?("key_cache") || ARGV.include?("row_cache") || ARGV.include?("counter_cache")  
                     true
                   end
  option :warn,
         description: 'Warning threshold for info metrics',
         short: '-w INFO_WARN',
         proc: proc {|a| a.to_f },
         required: true
  option :crit,
         description: 'Critical threshold for info metrics',
         short:'-c INFO_CRIT',
         proc: proc {|a| a.to_f },
         required: true

  option :tp_metric,
         description: 'ThreadPool metrics in cassandra',
         short: '-t TP_METRIC',
         proc: proc { |a| a.to_s}
 
  option :tp_warn,
         description: 'Warning threshold for threadPool metrics',
         short: '-W TP_WARN',
         proc: proc {|a| a.to_f },
         required: if ARGV.include?("-t")
                     true
                   end
  option :tp_crit,
         description: 'Critical threshold for threadPool metrics',
         short:'-C TP_CRIT',
         proc: proc {|a| a.to_f },
         required: if ARGV.include?("-t")
                     true
                   end

  option :cf_keyspace,
         description: 'Keyspace name for column family metrics',
         short: '-k CF_KEYSPACE',
         proc: proc { |a| a.to_s}
 
  option :cf_keyspace_metric,
         description: 'Keyspace metrics name',
         short: '-m CF_KEYSPACE_METRIC',
         proc: proc { |a| a.to_s},
         required: if ARGV.include?("-k")
                     true
                   end
  
  option :cf_table_name,
         description: 'Table name under a keyspace in column family metrics',
         short: '-T CF_KEYSPACE_METRIC',
         proc: proc { |a| a.to_s}

  option :cf_table_metric,
         description: 'Table metrics name',
         short: '-M CF_KEYSPACE_METRIC',
         proc: proc { |a| a.to_s},
         required: if ARGV.include?("-T")
                     true
                   end
  option :cf_warn,
         description: 'Warning threshold for column family metrics',
         short: '-a CF_WARN',
         proc: proc {|a| a.to_f },
         required: if ARGV.include?("-k")
                     true
                   end
  option :cf_crit,
         description: 'Critical threshold for column family metrics',
         short:'-b CF_CRIT',
         proc: proc {|a| a.to_f },
         required: if ARGV.include?("-k")
                     true
                   end
  
  $warn_queues = {}
  $crit_queues = {}
  
  def convert_to_bytes(size, unit)                          
    size.to_f * UNITS_FACTOR[unit]
  end

  def nodetool_cmd(cmd)
    `nodetool -h localhost -p 7199 #{cmd}`
  end
  
  def generate_message(status_hash)
    message = []
    status_hash.each_pair do |k, v|
      message << "#{k}: #{v}"
    end
    message.join(', ')
  end

  def parse_info
    info = nodetool_cmd('info')
    info.each_line do |line|
       case config[:info_metric]
       
         when "exceptions" 
           if m = line.match(/^(Exceptions)\s*:\s+([0-9]+)$/)
             $crit_queues[m[1]] = m[2].to_i if m[2].to_i >= config[:crit]
             $warn_queues[m[1]] = m[2].to_i if (m[2].to_i < config[:crit]) && (m[2].to_i >= config[:warn]) 
           end

         when "load"
           if m = line.match(/^(Load)\s*:\s+([0-9.]+)\s+([KMGT]i?B|bytes)$/)
             l = convert_to_bytes(m[2], m[3])
             $crit_queues[m[1]] = l if l >= convert_to_bytes(config[:crit],m[3])
             $warn_queues[m[1]] = l if (l < convert_to_bytes(config[:crit],m[3])) && (l >= convert_to_bytes(config[:warn],m[3]))
           end

         when "uptime"
           if m = line.match(/^(Uptime)[^:]+:\s+(\d+)$/)
             $crit_queues[m[1]] = m[2].to_i if m[2].to_i >= config[:crit]
             $warn_queues[m[1]] = m[2].to_i if (m[2].to_i < config[:crit]) && (m[2].to_i >= config[:warn])                                                                                                                                    
           end

         when "heap_memory"
           if m = line.match(/^(Heap Memory)[^:]+:\s+([0-9.]+)\s+\/\s+([0-9.]+)$/)
              if config[:info_sub_metric].eql?("heap_used")
                heap_used = convert_to_bytes(m[2], 'MB')
                $crit_queues["Heap Used"] = heap_used if heap_used >= convert_to_bytes(config[:crit], 'MB')                       
                $warn_queues["Heap Used"] = heap_used if (heap_used < convert_to_bytes(config[:crit], 'MB') ) && (heap_used >= convert_to_bytes(config[:warn], 'MB')) 
              end
              if config[:info_sub_metric].eql?("heap_total")  
                heap_total = convert_to_bytes(m[3], 'MB')                                      
                $crit_queues["Heap Total"] if heap_total <= convert_to_bytes(config[:crit], 'MB')                       
                $warn_queues["Heap Total"] if (heap_total > convert_to_bytes(config[:crit], 'MB')) && (heap_total <= convert_to_bytes(config[:warn], 'MB')) 
              end
            end 
            
         when "key_cache"
           if m = line.match(/^(Key Cache)[^:]+: entries ([0-9]+), size ([-+]?[0-9]*\.?[0-9]+) ([KMGT]i?B|bytes), capacity ([-+]?[0-9]*\.?[0-9]+) ([KMGT]i?B|bytes), ([0-9]+) hits, ([0-9]+) requests, ([-+]?[0-9]*\.?[0-9]+) recent hit rate/)
             if config[:info_sub_metric].eql?("size")
               size = convert_to_bytes(m[3], m[4])
               $crit_queues["key_cache.size"] = size if size >= convert_to_bytes(config[:crit], m[4])
               $warn_queues["key_cache.size"] = size if (size < convert_to_bytes(config[:crit],m[4])) && (size >= convert_to_bytes(config[:warn], m[4]))
             end
             if config[:info_sub_metric].eql?("capacity")
               capacity = convert_to_bytes(m[5], m[6])
               $crit_queues["key_cache.capacity"] = capacity if capacity >= convert_to_bytes(config[:crit], m[6])
               $warn_queues["key_cache.capacity"] = capacity if (capacity < convert_to_bytes(config[:crit],m[6])) && (capacity >= convert_to_bytes(config[:warn], m[6]))
             end
             if config[:info_sub_metric].eql?("hits")
               hits = m[7].to_i
               $crit_queues["key_cache.hits"] = hits if hits <= config[:crit].to_i
               $warn_queues["key_cache.hits"] = hits if (hits > config[:crit].to_i) && (hits <= config[:warn].to_i)
             end
             if config[:info_sub_metric].eql?("requests")
               requests = m[8].to_i
               $crit_queues["key_cache.requests"] = requests if requests <= config[:crit].to_i
               $warn_queues["key_cache.requests"] = requests if (requests > config[:crit].to_i) && (requests <= config[:warn].to_i)
             end
             if config[:info_sub_metric].eql?("hit_rate")
               hit_rate = m[9].to_f
               $crit_queues["key_cache.hit_rate"] = hit_rate if hit_rate <= config[:crit]
               $warn_queues["key_cache.hit_rate"] = hit_rate if (hit_rate > config[:crit]) && (hit_rate <= config[:warn]) 
             end
           end
            
         when "row_cache" 
           if m = line.match(/^Row Cache[^:]+: size ([0-9]+) \(bytes\), capacity ([0-9]+) \(bytes\), ([0-9]+) hits, ([0-9]+) requests/)
             if config[:info_sub_metric].eql?("size")
               size = m[1].to_f
               $crit_queues["row_cache.size"] = size if size >= config[:crit]
               $warn_queues["row_cache.size"] = size if (size < config[:crit]) && (size >= config[:warn]) 
             end
             if config[:info_sub_metric].eql?("capacity")
               capacity = m[2].to_f
               $crit_queues["row_cache.capacity"] = capacity if capacity >= config[:crit]
               $warn_queues["row_cache.capacity"] = capacity if (capacity < config[:crit]) && (capacity >= config[:warn]) 
             end
             if config[:info_sub_metric].eql?("hits")
               hits = m[3].to_i
               $crit_queues["row_cache.hits"] = hits if hits <= config[:crit].to_i
               $warn_queues["row_cache.hits"] = hits if (hits > config[:crit].to_i) && (hits <= config[:warn].to_i) 
             end
             if config[:info_sub_metric].eql?("requests")
               requests = m[4].to_i
               $crit_queues["row_cache.requests"] = requests if requests <= config[:crit].to_i
               $warn_queues["row_cache.requests"] = requests if (requests > config[:crit].to_i) && (requests <= config[:warn].to_i) 
             end
           end

         when "counter_cache"
           if m = line.match(/^(Counter Cache)[^:]+: entries ([0-9]+), size ([-+]?[0-9]*\.?[0-9]+) ([KMGT]i?B|bytes), capacity ([-+]?[0-9]*\.?[0-9]+) ([KMGT]i?B|bytes), ([0-9]+) hits, ([0-9]+) requests, ([-+]?[0-9]*\.?[0-9]+) recent hit rate/)
             if config[:info_sub_metric].eql?("size")
               size = convert_to_bytes(m[3], m[4])
               $crit_queues["counter_cache.size"] = size if size >= convert_to_bytes(config[:crit], m[4])
               $warn_queues["counter_cache.size"] = size if (size < convert_to_bytes(config[:crit],m[4])) && (size >= convert_to_bytes(config[:warn], m[4]))
             end
             if config[:info_sub_metric].eql?("capacity")
               capacity = convert_to_bytes(m[5], m[6])
               $crit_queues["counter_cache.capacity"] = capacity if capacity >= convert_to_bytes(config[:crit], m[6])
               $warn_queues["counter_cache.capacity"] = capacity if (capacity < convert_to_bytes(config[:crit],m[6])) && (capacity >= convert_to_bytes(config[:warn], m[6]))
             end
             if config[:info_sub_metric].eql?("hits")
               hits = m[7].to_i
               $crit_queues["countercache.hits"] = hits if hits <= config[:crit].to_i
               $warn_queues["counter_cache.hits"] = hits if (hits > config[:crit].to_i) && (hits <= config[:warn].to_i)
             end
             if config[:info_sub_metric].eql?("requests")
               requests = m[8].to_i
               $crit_queues["counter_cache.requests"] = requests if requests <= config[:crit].to_i
               $warn_queues["counter_cache.requests"] = requests if (requests > config[:crit].to_i) && (requests <= config[:warn].to_i)
             end
             if config[:info_sub_metric].eql?("hit_rate")
               hit_rate = m[9].to_f
               $crit_queues["counter_cache.hit_rate"] = hit_rate if hit_rate <= config[:crit]
               $warn_queues["counter_cache.hit_rate"] = hit_rate if (hit_rate > config[:crit]) && (hit_rate <= config[:warn]) 
             end
           end
         else
           puts "Please enter a valid metric"
       end
    end
  end

  def parse_tpstats
    tpstats = nodetool_cmd('tpstats')
    tpstats.each_line do |line| 
       next if line =~ /^Pool Name/
       next if line =~ /^Message type/ 

       if m = line.match(/^(\w+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)$/)
         (thread, active, pending, completed, blocked) = m.captures
         if thread.eql?(config[:tp_metric])
           $crit_queues[thread] = active.to_i if active.to_i <= config[:tp_crit].to_i
           $warn_queues[thread] = active.to_i if (active.to_i > config[:tp_crit].to_i) && (active.to_i <= config[:tp_warn].to_i) 
         end
       end

      if m = line.match(/^(\w+)\s+(\d+)$/)
        (message_type, dropped) = m.captures
        if message_type.eql?(config[:tp_metric])
          $crit_queues[message_type] = dropped if dropped.to_i >= config[:tp_crit].to_i
          $warn_queues[message_type] = dropped if (dropped.to_i < config[:tp_crit].to_i) && (dropped.to_i >= config[:tp_warn].to_i)
        end
      end
    end
  end

  def parse_cfstats
    def get_metric(string) 
      string.strip!
      (metric, value) = string.split(': ')
      puts value
      if metric.nil? || value.nil? 
        return [nil, nil]
      else
        metric.gsub!(/[^a-zA-Z0-9]/, '_')  # convert all other chars to _
        metric.gsub!(/[_]*$/, '')          # remove any _'s at end of the string
        metric.gsub!(/[_]{2,}/, '_')       # convert sequence of multiple _'s to single _
        metric.downcase!
        # sanitize metric values. Numbers only, please.
        value = value.chomp(' ms.').gsub(/([0-9.]+)$/, '\1')
      end
      [metric, value]
    end

    cfstats = nodetool_cmd('cfstats')

    keyspace = nil
    cf = nil
    flag = 0
    cfstats.each_line do |line|
      num_indents = line.count("\t")
      if line.include?(config[:cf_keyspace]) || flag == 1  
        if m = line.match(/^Keyspace\s?:\s+(\w+)$/)
          keyspace = m[1]
          flag += 1
        elsif (m = line.match(/\t\tTable[^:]*:\s+(\w+)$/)) && line.include?(config[:cf_table_name])
          cf = m[1]
        elsif num_indents == 0
          cf = nil
        elsif num_indents == 2 && !cf.nil? && line.include?(config[:cf_table_metric])
          # a column metric
          (metric, value) = get_metric(line)
          case metric
            when "sstable_count"
              $crit_queues[metric] = value if value >= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value < config[:cf_crit].to_i) && (value >= config[:cf_warn].to_i)
	    when "space_used_live"
              $crit_queues[metric] = value if value >= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value < config[:cf_crit].to_i) && (value >= config[:cf_warn].to_i)
            when "space_used _total"
              $crit_queues[metric] = value if value >= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value < config[:cf_crit].to_i) && (value >= config[:cf_warn].to_i)
	    when "off_heap_memory_used_total" 
              $crit_queues[metric] = value if value >= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value < config[:cf_crit].to_i) && (value >= config[:cf_warn].to_i)
	    when "sstable_compression_ratio"
              $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn])
	    when "number_of_partitions_estimate"
              $crit_queues[metric] = value if value >= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value < config[:cf_crit].to_i) && (value >= config[:cf_warn].to_i)
            when "memtable_cell_count"
              $crit_queues[metric] = value if value >= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value < config[:cf_crit].to_i) && (value >= config[:cf_warn].to_i)
            when "memtable_data_size"
              $crit_queues[metric] = value if value >= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value < config[:cf_crit].to_i) && (value >= config[:cf_warn].to_i)
	    when "memtable_off_heap_memory_used"
	      $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn])
            when "local_read_count"
              $crit_queues[metric] = value if value <= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value > config[:cf_crit].to_i) && (value <= config[:cf_warn].to_i)
            when "local_read_latency"
              $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn])
            when "local_write_count"
              $crit_queues[metric] = value if value <= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value > config[:cf_crit].to_i) && (value <= config[:cf_warn].to_i)
            when "local_write_latency"
              $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn])
	    when "pending_flushes"
              $crit_queues[metric] = value if value >= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value < config[:cf_crit].to_i) && (value >= config[:cf_warn].to_i)
            when "bloom_filter_false_positives"
              $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn])
	    when "bloom_filter_false_ratio"
              $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn])
	    when "bloom_filter_space_used"
              $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn])
	    when "bloom_filter_off_heap_memory_used"
              $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn])
            when "compacted_partition_minimum_bytes"
              $crit_queues[metric] = value if value <= config[:cf_crit]
              $warn_queues[metric] = value if (value > config[:cf_crit]) && (value <= config[:cf_warn])
	    when "compacted_partition_maximum_bytes"
              $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn])
	    when "compacted_partition_mean_bytes"
              $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn])
          end
        elsif num_indents == 1 && !keyspace.nil? && line.include?(config[:cf_keyspace_metric])
          # a keyspace metric
          (metric, value) = get_metric(line)
          case metric
            when "read_count"
              $crit_queues[metric] = value if value <= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value > config[:cf_crit].to_i) && (value <= config[:cf_warn].to_i)
            
            when "read_latency"
              $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn])
          
            when "write_count"
              $crit_queues[metric] = value if value <= config[:cf_crit].to_i
              $warn_queues[metric] = value if (value > config[:cf_crit].to_i) && (value <= config[:cf_warn].to_i)

            when "write_latency"
              $crit_queues[metric] = value if value >= config[:cf_crit]
              $warn_queues[metric] = value if (value < config[:cf_crit]) && (value >= config[:cf_warn]) 
             
          end
        end
      end
    end
  end
  
  def run
    info = parse_info if ARGV.include?("-i")
    tp_stats = parse_tpstats if ARGV.include?("-t")
    cf_stats = parse_cfstats if ARGV.include?("-k")
    if info.empty? || tp_stats.empty? || cf_stats
       message "Unable to connect to localhost 7199"
       warning
    end
    message $crit_queues.empty? ? ($warn_queues.empty? ? "RUNNING" : generate_message($warn_queues) ) : generate_message($crit_queues)
    critical unless $crit_queues.empty?
    warning unless $warn_queues.empty?
    ok if ($crit_queues.empty?) && ($warn_queues.empty?)

  end
end
