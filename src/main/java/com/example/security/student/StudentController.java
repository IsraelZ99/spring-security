package com.example.security.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Israel"),
            new Student(2, "Monserrat"),
            new Student(3, "Jose"),
            new Student(4, "Mariana")
    );

    @GetMapping("/{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId){
        return STUDENTS.stream()
                .filter(student -> studentId == student.getStudentId())
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Student "+studentId+ " does not exists"));
    }

}
