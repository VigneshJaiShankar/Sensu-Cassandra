#This file gives details about how to give monitoring values for command property in cassandra-check.json in sensu using the below command. 

COMMAND_USAGE:

# check-cassandra.rb [-i info_metric]  [-s info_sub_metric] [-w info_warn] [-c info_crit] [-t tp_metric] [-W tp_warn] [-C tp_crit] [-k cf_keyspace_name] [-m cf_keyspace_metric] [-T cf_table_name] [-M cf_table_metric] [-a cf_warn] [-b cf_crit]


option :info_metric  (Info metrics)

        #This option is used for getting the info metric name. 
        
        #Available values: exceptions, load, uptime, heap_memory, key_cache, row_cache, counter_cache

option :info_sub_metric
        
       #This option is used when the info_metric is either heap_memory or key_cache or row_cache or counter_cache  

       #Available values: 
          #If info_metric is heap_memory the values are: heap_used, heap_total 

          #If info_metric is key_cache or row_cache or counter_cache the values are: size, capacity, hits, requests, hit_rate                  
       
option :info_warn
       
       #This option is used for setting warning threshold for the specified info_metric

option :info_crit

       #This option is used for setting critical threshold for the specified info_metric

option :tp_metric (Threadpool metrics)
 
       #This option is used for getting threadpool metric name.
    
       #Available values for thread metrics: ReadStage, MiscStage, CompactionExecutor, MutationStage, MemtableReclaimMemory, PendingRangeCalculator, GossipStage, SecondaryIndexManagement, HintsDispatcher, RequestResponseStage, Native-Transport-Requests, ReadRepairStage, CounterMutationStage, MigrationStage, MemtablePostFlush, PerDiskmemtableFlushWriter_0, ValidationExecutor, Sample, MemtableFlushWriter, InternalResponseStage, ViewMutationStage, AntiEntropyStage, CacheCleanupExecutor
    
       #Available values for message type in thread metrics: READ, RANGE_SLICE, _TRACE, HINT, MUTATION, COUNTER_MUTATION, BATCH_STORE, BATCH_REMOVE, REQUEST_RESPONSE, PAGED_RANGE, READ_REPAIR                

option :tp_warn
    
       #This option is used for setting warning threshold for the specified threadpool_metric

       #When thread metrics is given the threshold value mentioned is for checking active value.
 
       #When message metrics is given the threshold value mentioned is for checking dropped value.  

option :tp_crit

       #This option is used for setting critical threshold for the specified threadpool_metric

       #When thread metrics is given the threshold value mentioned is for checking active value.
 
       #When message metrics is given the threshold value mentioned is for checking dropped value.

option :cf_keyspace_name

       #This option is used for getting keyspace name in column family metrics

       #Available values are: system_traces, system, system_distributed, system_schema, system_auth

option :cf_keyspace_metric
   
       #Available values are: read_count, read_latency, write_count, write_latency 

option :cf_table_name
   
       #This option is used for getting table name for the specified keyspace.The available tables under each keyspaces are given below.

           #system_traces: events, sessions
       
           #system: IndexInfo, available_ranges, batches, batchlog, built_views, compaction_history, hints, local, paxos, peer_events, peers, prepared_statements, range_xfers, size_estimates, sstable_activity, transferred_ranges, views_builds_in_progress

           #system_distributed: parent_repair_history, repair_history, view_build_status

           #system_schema: aggregates, columns, dropped_columns, functions, indexes, keyspaces, tables, triggers, types, views

           #system_auth: resource_role_permissions_index, role_members, role_permissions, roles

option :cf_table_metric

       #This option is used for getting the metric to be checked for the specified table_name.

       #Available values are: sstable_count, space_used_live, space_used_total, off_heap_memory_used_total, sstable_compression_ratio, number_of_partitions_estimate, memtable_cell_count, memtable_data_size, memtable_off_heap_memory_used, local_read_count, local_read_latency, local_write_count, local_write_latency, pending_flushes, bloom_filter_false_positives, bloom_filter_false_ratio, bloom_filter_space_used, bloom_filter_off_heap_memory_used, compacted_partition_minimum_bytes, compacted_partition_maximum_bytes, compacted_partition_mean_bytes

option :cf_warn

       #This option is used for setting warning threshold for either metrics under keyspace or table.
 
option :cf_crit

       #This option is used for setting critical threshold for either metrics under keyspace or table.
