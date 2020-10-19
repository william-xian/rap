
// stub module to test header files' C++ compatibility

extern "C" {
  #include <rap_config.h>
  #include <rap_core.h>
  #include <rap_event.h>
  #include <rap_event_connect.h>
  #include <rap_event_pipe.h>

  #include <rap_http.h>

  #include <rap_mail.h>
  #include <rap_mail_pop3_module.h>
  #include <rap_mail_imap_module.h>
  #include <rap_mail_smtp_module.h>
}

// rap header files should go before other, because they define 64-bit off_t
// #include <string>


void rap_cpp_test_handler(void *data);

void
rap_cpp_test_handler(void *data)
{
    return;
}
