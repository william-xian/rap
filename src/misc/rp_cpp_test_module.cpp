
// stub module to test header files' C++ compatibility

extern "C" {
  #include <rp_config.h>
  #include <rp_core.h>
  #include <rp_event.h>
  #include <rp_event_connect.h>
  #include <rp_event_pipe.h>

  #include <rp_http.h>

  #include <rp_mail.h>
  #include <rp_mail_pop3_module.h>
  #include <rp_mail_imap_module.h>
  #include <rp_mail_smtp_module.h>
}

// rap header files should go before other, because they define 64-bit off_t
// #include <string>


void rp_cpp_test_handler(void *data);

void
rp_cpp_test_handler(void *data)
{
    return;
}
