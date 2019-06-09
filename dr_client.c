
#define _CRT_SECURE_NO_WARNINGS

#include "dr_api.h"
#include "drmgr.h"
#include "drx.h"
#include "drreg.h"
#include "drwrap.h"

#include <string.h>
#include <stdlib.h>
#include <windows.h>

dr_mcontext_t safed_memoryContext;
#define SIZE_OF_STACK_TO_SAVE	500
#define ARGUMENT_BUFFER_SIZE 100

char old_stack_context[SIZE_OF_STACK_TO_SAVE];
int number_iterations = 0;

static void
event_exit(void);

#define MAX_NUM_MODULES 0x1000

typedef struct _module_array_t {
    app_pc base;
    app_pc end;
    bool loaded;
    module_data_t *data;
} module_array_t;

static module_array_t mod_array[MAX_NUM_MODULES];


app_pc start_offset = (app_pc)0x40135b;
app_pc end_offset = (app_pc)0x40136e;

static bool
onexception(void *drcontext, dr_exception_t *excpt) {
    DWORD exception_code = excpt->record->ExceptionCode;

   
    if((exception_code == EXCEPTION_ACCESS_VIOLATION) ||
       (exception_code == EXCEPTION_ILLEGAL_INSTRUCTION) ||
       (exception_code == EXCEPTION_PRIV_INSTRUCTION) ||
       (exception_code == EXCEPTION_INT_DIVIDE_BY_ZERO) ||
       (exception_code == STATUS_HEAP_CORRUPTION) ||
       (exception_code == EXCEPTION_STACK_OVERFLOW) ||
       (exception_code == STATUS_STACK_BUFFER_OVERRUN) ||
       (exception_code == STATUS_FATAL_APP_EXIT)) {
       
       
        dr_exit_process(1);
    }
    return true;
}

static void pre_fuzzing(void *wrapcxt, INOUT void **user_data){
	
	dr_fprintf(STDOUT, "pre_fuzzing\n");
	/*
	size_t tmp_size;
	
	void *drcontext = dr_get_current_drcontext();
	
	memset(&safed_memoryContext, 0x00, sizeof(dr_mcontext_t));
	memset(old_stack_context, 0x00, SIZE_OF_STACK_TO_SAVE);
	
	safed_memoryContext.size = sizeof(dr_mcontext_t);
	safed_memoryContext.flags = DR_MC_ALL;
	bool ret = dr_get_mcontext(drcontext, &safed_memoryContext);
	if(ret == false){
		dr_fprintf(STDERR, "Could not get memory context in pre handler!\n");
		return;
		
	}
	dr_safe_read(safed_memoryContext.xsp, SIZE_OF_STACK_TO_SAVE, old_stack_context, &tmp_size);
	
	//new_argument_buffer = dr_global_alloc(ARGUMENT_BUFFER_SIZE);
	
	*/
	
}

static void post_fuzzing(void *wrapcxt, INOUT void **user_data){
	
	dr_fprintf(STDOUT, "post_fuzzing\n");
	/*
	size_t tmp_size;
	
	void *drcontext = dr_get_current_drcontext();
	
	dr_mcontext_t mc;
	
	memset(&mc, 0x00, sizeof(dr_mcontext_t));
	
	mc.size = sizeof(dr_mcontext_t);
	mc.flags = DR_MC_INTEGER;
	bool ret = dr_get_mcontext(drcontext, &mc);
	if(ret == false){
		dr_fprintf(STDERR, "Could not get memory context in post handler!\n");
		return;
		
	}
	

	number_iterations++;
	if(number_iterations == 1000){
			
		dr_exit_process(0);
	}
		

	dr_set_mcontext(drcontext, &safed_memoryContext);
	dr_safe_write(safed_memoryContext.xsp, SIZE_OF_STACK_TO_SAVE, old_stack_context, &tmp_size);
	*/
	/*
	dr_snprintf(new_arguement_buffer, ARGUMENT_BUFFER_SIZE, "foobar%d", number_iterations);
	dr_safe_write(safed_memoryContext.xsp + 0x08, 4, &new_argument_buffer, &tmp_size);
	size_t new_argument_size = strlen(new_argument_buffer);
	dr_safe_write(safed_memoryContext.xsp + 0x0c, 4, &new_argument_size, &tmp_size);
	new_argument_buffer = dr_global_alloc(ARGUMENT_BUFFER_SIZE);
	*/
	//dr_redirect_execution(&safed_memoryContext);
}



static dr_emit_flags_t
instrument_bb_coverage(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
	
		drmgr_disable_auto_predication(drcontext, bb);
    if (!drmgr_is_first_instr(drcontext, instr))
        return DR_EMIT_DEFAULT;


		app_pc instruction_address;
		instruction_address = instr_get_app_pc(instr);
    
    

		if(instruction_address == start_offset){
    	dr_fprintf(STDOUT, "0x%x\n", instruction_address);
    	dr_insert_clean_call(drcontext, bb, instr, (void *)pre_fuzzing, false, 0);
    	}
    else if(instruction_address == end_offset){
    	dr_fprintf(STDOUT, "0x%x\n", instruction_address);
    	dr_insert_clean_call(drcontext, bb, instr, (void *)post_fuzzing, false, 0);
   	}

		return DR_EMIT_DEFAULT;
}


static void
event_module_unload(void *drcontext, const module_data_t *info)
{
		//dr_fprintf(STDOUT, "module : %s\n", info->names.exe_name);
    //module_table_unload(module_table, info);
}

static void
event_module_load(void *drcontext, const module_data_t *info, bool loaded)
{
		
    const char *module_name = info->names.exe_name;
    if (module_name == NULL) {
        module_name = dr_module_preferred_name(info);
    }
		dr_fprintf(STDOUT, "module : %s\n", module_name);
		bool ok;
		if(strcmp(module_name, "test.exe") == 0) {
						dr_fprintf(STDOUT,  "\t=>base addres : 0x%x\n", info->start);
						dr_fprintf(STDOUT,  "\t=>handle : 0x%x\n", info->handle);
						//app_pc to_wrap = (app_pc)dr_get_proc_address(info->handle, "start");

				
            //drwrap_wrap_ex(start_offset, pre_fuzz_handler, post_fuzz_handler, NULL, options.callconv);
            dr_fprintf(STDOUT, "\t=>drwrap : 0x%x\n", start_offset);
            ok = drwrap_wrap(start_offset, pre_fuzzing, post_fuzzing);
            if (!ok)
				    {
				      dr_fprintf(STDERR, "[-] Could not wrap 'start_offset': already wrapped?\n");
				      DR_ASSERT(ok);
				    }
            ok = false;
            dr_fprintf(STDOUT, "\t=>drwrap : 0x%x\n", end_offset);
            
            ok = drwrap_wrap(end_offset, post_fuzzing, NULL);
            if (!ok)
				    {
				      dr_fprintf(STDERR, "[-] Could not wrap 'end_offset': already wrapped?\n");
				      DR_ASSERT(ok);
				    }
				    
    }
                    
    //module_table_load(module_table, info);
}

static void
event_exit(void)
{
		drwrap_exit();
  	drmgr_exit();
  	 
    /* destroy module table */
    //module_table_destroy(module_table);

}

static void
event_init(void)
{
   // module_table = module_table_create();

}


static void
options_init(client_id_t id, int argc, const char *argv[])
{
    int i;

}

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
		
		dr_set_client_name("InMemoryFuzzing", "");
		
		//dr_log(NULL, DR_LOG_ALL, 1, "Client 'wrap' initializing\n");

		dr_enable_console_printing();
		drmgr_init();
    drwrap_init();

		dr_fprintf(STDOUT, "app name : %s\n", dr_get_application_name());
		options_init(id, argc, argv);

		/*if(_strnicmp(dr_get_application_name(), application_name, strlen(application_name)) == 0){
			
			if(exit_child_process == true){
				dr_exit_process(0);
			}
			
		}*/

    dr_register_exit_event(event_exit);

    drmgr_register_exception_event(onexception);
    drmgr_register_module_load_event(event_module_load);
		drmgr_register_bb_instrumentation_event(NULL, instrument_bb_coverage, NULL);
    
    drmgr_register_module_unload_event(event_module_unload);
  
  	event_init();
}
