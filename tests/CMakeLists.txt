add_executable(test_qpg test_qpg.c)

target_link_libraries(test_qpg PRIVATE qpg_lib)

add_test(NAME test_qpg COMMAND test_qpg)
