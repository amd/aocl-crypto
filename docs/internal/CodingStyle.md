---
title: AOCL Crypto Coding Style
subtitle: Coding Style Reference Document
subject: "markdown"
keywords: [books,programming]
language: en-US
#cover-image: img/example-book-cover.png
lof: true
lof-own-page: true
toc-own-page: true
titlepage: true
#;titlepage-background: backgrounds/background10.pdf
#titlepage-text-color: "333333"
#titlepage-rule-color: "00737C"
papersize: a4
#prepend-titlepage: img/example-book-cover.pdf
colorlinks: true
---

# Naming

Allowed Cases:

* lower_case

 * UPPER_CASE
 * camelBack
 * CamelCase
 * camel_Snake_Back
 * aNy_CasE
 * Camel_Snake_Case
  

## Abstract Class

* AbstractClassCase    - CamelCase
* AbstractClassPrefix  - Abstract
* AbstractClassSuffix  - NA

``` c++
class model {
public:
  model();
};
```

After:

```c++
class AbstractModel {
public:
	AbstractModel();
}
```

## Class 

- ClassCase	- CamelCase
- ClassPrefix  - None
- ClassSuffix  - None

``` c++
class model_blah {
public:
  model();
};
```

After:

```c++
class ModelBlah {
public:
	ModelBlah();
}
```


## Class Constants

- ClassConstantCase  	- CamelCase

- ClassConstantPrefix	- c 
- ClassConstantSuffix    - NA

```c++
class FOO {
public:
  static const int CLASS_CONSTANT;
};
```

After:
```c++
class FOO {
public:
  static const int cClassConstant;
};
```

## Class Member

- ClassMemberCase	  - lower_case

- ClassMemberPrefix	- m_
- ClassMemberSuffix	- NA

```c++
class FOO {
public:
  static int 	CLASS_MEMBER;
  int 			another_class_member;
};
```

After:
```c++
class FOO {
public:
  static int m_class_member;
  int 		 m_another_class_member;
};
```

## Class Method (member function)

Class methods should use 'camelBack' case with no prefix or suffix.

- ClassMethodCase	  - camelBack

- ClassMethodPrefix	- NA 
- ClassMethodSuffix	- NA

```c++
class FOO {
public:
  int CLASS_MEMBER();
};
```

After:
```c++
class Foo {
public:
  int classMember();
};
```

## Constants

- ConstantCase	  - CamelCase

- ConstantPrefix	- c
- ConstantSuffix	- NA

```c++
void function() { unsigned const MyConst_array[] = {1, 2, 3}; }
```
After:
```c++
void function() { unsigned const cMyconstArray[] = {1, 2, 3}; }
```

## Constant Members of a class

- ConstantMemberCase	  - CamelCase

- ConstantMemberPrefix	- c
- ConstantMemberSuffix	- NA

```c++
class Foo {
  char const MY_ConstMember_string[4] = "123";
}
```

After:
```c++
class Foo {
  char const cMyConstmemberString[4] = "123";
}
```

## Constant Parameter 
- ConstantParameterCase	  - CamelCase
- ConstantParameterPrefix	- c
- ConstantParameterSuffix	- NA

```c++
void GLOBAL_FUNCTION(int PARAMETER_1, int const CONST_parameter);
```

After:
```c++
void GLOBAL_FUNCTION(int PARAMETER_1, int const cConstParameter);
```


## Constant Pointer Parameter 
- ConstantPointerParameterCase 	- CamelCase

- ConstantPointerParameterPrefix	- pc
- ConstantPointerParameterSuffix	- NA

```c++
void GLOBAL_FUNCTION(int const *CONST_parameter);
```

After:
```c++
void GlobalFunction(int const *pcConstParameter);
```

## Constexpr Function 

Follow same naming conventions for 
GlobalFunctionCase and no prefix or suffix is needed for Global constexpr function.
and MethodCase with no prefix or suffix for Method constexpr functions

- ConstexprFunctionCase	  - GlobalFunctionCase

- ConstexprFunctionPrefix	- NA
- ConstexprFunctionSuffix	- NA

```c++
constexpr int CE_function() { return 3; }
```

After:
```c++
constexpr int Function() { return 3; }
```

## Constexpr Method
Follow same naming conventions of MethodCase with no prefix or suffix for Method constexpr functions.

- 
  ConstexprMethodCase  	- MethodCase (camelBack)

- ConstexprMethodPrefix	- NA
- ConstexprMethodSuffix	- NA

```c++
class Foo {
public:
  constexpr int CONST_expr_Method() { return 2; }
}
```

After:
```c++
class Foo {
public:
  constexpr int constExprMethod() { return 2; }
}
```

## Constexpr Variable

- ConstexprVariableCase

- ConstexprVariablePrefix
- ConstexprVariableSuffix

```c++
constexpr int ConstExpr_variable = MyConstant;
```

After:
```c++
constexpr int pre_constexpr_variable_post = MyConstant;
```

## Enumerations 

- EnumCase	  - CamelCase

- EnumPrefix	- NA
- EnumSuffix	- NA

```c++
enum FOO { One, Two, Three };
     ^^^
```

After:
```c++
enum Foo { One, Two, Three };
     ^^^
```

## Enumeration Constant

Follow Enumeration style.

- EnumConstantCase	  - CamelCase

- EnumConstantPrefix	- e
- EnumConstantSuffix	- NA

```c++
enum FOO { One, Two, Three };
```

After:
```c++
enum Foo { eOne, eTwo, eThree };
          ^^    ^^    ^^
```

## Function
Functions are global entities (others are Methods). Both Static and non-static global functions use the same style.

- FunctionCase  	- CamelCase

- FunctionPrefix	- NA
- FunctionSuffix	- NA

```c++
char MY_Function_string();
```
After:
```c++
char MyFunctionString();
```

## Global Constant

- GlobalConstantCase	  - CamelCase

- GlobalConstantPrefix	- gc
- GlobalConstantSuffix	- NA

```c++
unsigned const MyConstGlobal_array[] = {1, 2, 3};
```
After:
```c++
unsigned const gcMyConstGlobalArray[] = {1, 2, 3};
```

## Global Constant Pointer 

- GlobalConstantPointerCase	  - gp

- GlobalConstantPointerPrefix	- NA
- GlobalConstantPointerSuffix	- NA

```c++
int *const MyConstantGlobalPointer = nullptr;
```

After:
```c++
int *const gpcMyConstantGlobalPointer = nullptr;
```

## Global Constant Function
- GlobalFunctionCase	  - CamelCase

- GlobalFunctionPrefix	- NA
- GlobalFunctionSuffix	- NA

```c++
void GLOBAL_FUNCTION(int PARAMETER_1, int const CONST_parameter);
```
After:
```c++
void GlobalFunction(int PARAMETER_1, int const CONST_parameter);
```

## Global Pointer

- GlobalPointerCase

- GlobalPointerPrefix
- GlobalPointerSuffix

```c++
int *GLOBAL3;

```
After:
```c++
int *pre_global3_post;
```

## Global Variable 
- GlobalVariableCase

- GlobalVariablePrefix
- GlobalVariableSuffix

```c++
int GLOBAL3;
```

After:
```c++
int pre_global3_post;
```

## Inline Namespace
- InlineNamespaceCase

- InlineNamespacePrefix
- InlineNamespaceSuffix

```c++
namespace FOO_NS {
inline namespace InlineNamespace {
...
}
} // namespace FOO_NS
```

After:
```c++
namespace FOO_NS {
inline namespace pre_inlinenamespace_post {
...
}
} // namespace FOO_NS
```


## Local Constant
- LocalConstantCase	  	- lower_case

- LocalConstantPrefix		- c_
- LocalConstantSuffix		- NA

```c++
void foo() { int const local_Constant = 3; }
```

After:
```c++
void foo() { int const c_local_constant = 3; }
```


## Local Constant 
- LocalConstantPointerCase	  - lower_case

- LocalConstantPointerPrefix	- p_
- LocalConstantPointerSuffix	- NA

```c++
void foo() { int const *local_var = 3; }
```

After:
```c++
void foo() { int const *cp_local_var = 3; }
```

## Local Pointer 
- LocalPointerCase

- LocalPointerPrefix
- LocalPointerSuffix

```c++
void foo() { int *local_Variable; }
```

After:
```c++
void foo() { int *p_local_var; }
```

## Local Variable 
- LocalVariableCase
- LocalVariablePrefix
- LocalVariableSuffix

```c++
void foo() { int local_Variable; }
```

After:
```c++
void foo() { int local_var; }
```

## Member Variable 
- MemberCase
- MemberPrefix
- MemberSuffix

```c++
```

After:
```c++
```

## Methods
- MethodCase
- MethodPrefix
- MethodSuffix

```c++
```

After:
```c++
```

## Namespace 
- NamespaceCase
- NamespacePrefix
- NamespaceSuffix

```c++
```

After:
```c++
```

## Function Parameters 
- ParameterCase
- ParameterPrefix
- ParameterSuffix

```c++
```

After:
```c++
```

## Parameter Packs 
- ParameterPackCase
- ParameterPackPrefix
- ParameterPackSuffix

```c++
```

After:
```c++
```

## Pointer Parameter 
- PointerParameterCase
- PointerParameterPrefix
- PointerParameterSuffix

```c++
```

After:
```c++
```

## Private members
- PrivateMemberCase
- PrivateMemberPrefix
- PrivateMemberSuffix

```c++
```

After:
```c++
```

## Private Methods
- PrivateMethodCase
- PrivateMethodPrefix
- PrivateMethodSuffix

```c++
```

After:
```c++
```

## Protected Members
- ProtectedMemberCase
- ProtectedMemberPrefix
- ProtectedMemberSuffix

```c++
```

After:
```c++
```

## Protected Methods
- ProtectedMethodCase
- ProtectedMethodPrefix
- ProtectedMethodSuffix

```c++
```

After:
```c++
```

## Public Members
- PublicMemberCase
- PublicMemberPrefix
- PublicMemberSuffix

```c++
```

After:
```c++
```

## Public Methods
- PublicMethodCase
- PublicMethodPrefix
- PublicMethodSuffix

```c++
```

After:
```c++
```

## Static Constants
- StaticConstantCase
- StaticConstantPrefix
- StaticConstantSuffix

```c++
```

After:
```c++
```

## Static Variables
- StaticVariableCase
- StaticVariablePrefix
- StaticVariableSuffix

```c++
```

After:
```c++
```

## Structures
- StructCase
- StructPrefix
- StructSuffix

```c++
```

After:
```c++
```

## Template Parameters
- TemplateParameterCase
- TemplateParameterPrefix
- TemplateParameterSuffix

```c++
```

After:
```c++
```

## Template Template Parameters
- TemplateTemplateParameterCase
- TemplateTemplateParameterPrefix
- TemplateTemplateParameterSuffix

```c++
```

After:
```c++
```

## Type Aliases
- TypeAliasCase
- TypeAliasPrefix
- TypeAliasSuffix

```c++
```

After:
```c++
```

## Typedefs
- TypedefCase
- TypedefPrefix
- TypedefSuffix

```c++
```

After:
```c++
```

## Type Template Parameters
- TypeTemplateParameterCase
- TypeTemplateParameterPrefix
- TypeTemplateParameterSuffix

```c++
```

After:
```c++
```

## Union 
- UnionCase
- UnionPrefix
- UnionSuffix

```c++
```

After:
```c++
```

## Value Template 
- ValueTemplateParameterCase
- ValueTemplateParameterPrefix
- ValueTemplateParameterSuffix

```c++
```

After:
```c++
```

## Variable 
- VariableCase
- VariablePrefix
- VariableSuffix

```c++
```

After:
```c++
```

## Virtual Method
- VirtualMethodCase
- VirtualMethodPrefix
- VirtualMethodSuffix

```c++
```

After:
```c++
```


# Example .clang-tidy file

```json

Checks: '-*,readability-identifier-naming'
CheckOptions:
  - { key: readability-identifier-naming.NamespaceCase,       value: lower_case }
  - { key: readability-identifier-naming.ClassCase,           value: CamelCase  }
  - { key: readability-identifier-naming.PrivateMemberPrefix, value: m_         }
  - { key: readability-identifier-naming.StructCase,          value: CamelCase  }
  - { key: readability-identifier-naming.FunctionCase,        value: lower_case }
  - { key: readability-identifier-naming.VariableCase,        value: lower_case }
  - { key: readability-identifier-naming.GlobalConstantCase,  value: UPPER_CASE }
  
```
