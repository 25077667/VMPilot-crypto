set(INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR})

set(SOURCES main.cpp)
set(LIBRARIES crypto)

include_directories(${INCLUDE_DIRECTORIES})
add_executable(${PROJECT_NAME} ${SOURCES})

target_link_libraries(${PROJECT_NAME} PRIVATE ${LIBRARIES})