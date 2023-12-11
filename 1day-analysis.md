### CVE-2018-18820 snprintf 취약점 분석

- sprintf vs snprintf

sprintf과 snprintf의 원형은 아래와 같이 정의되어 있다.

```ccodeql
#include <stdio.h>
int sprintf(char *buffer, const char *format-string, argument-list);
int snprintf(char *buffer, size_t n, const char *format-string, argument-list);
```

sprintf() 함수는 포맷 스트링 변수가 사용될 때 BOF 문제가 발생할 수 있고 그를 대체하기 위해 버퍼에 출력되는 데이터의 길이를 제한하기 위해 snprintf() 함수를 사용할 수 있다. 

아래 프로그램은 사용자가 인풋에 대한 경계가 없으므로 BOF가 발생한다. 

```c
#include <stdio.h>

int main(){
        char buf[10];
        char input[10];
        scanf("%s",input);
        sprintf(buf,"AAAA%s",input);
        printf("%s",buf);
}
```

```
$ ./sprintf_test
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
[1]    863 segmentation fault  ./sprintf_test

► 0x40062a <main+84>    ret    <0x4141414141414141>
```

sprintf() 함수에서 포맷 스트링 변수가 사용될 때 BOF문제가 발생할 수 있다. 그래서 버퍼에 출력되는 데이터의 길이를 제한하기 위해 snprintf() 함수를 사용한다. 이 함수는 데이터의 길이가 버퍼보다 더 크면 기록하지 않는다. 위의 sprintf()를 대체해 아래처럼 사용할 수 있다.

```c
if(snprintf(buf,sizeof(buf)-1,"%s",input) > sizeof(input)-1){
        /* ... */
}
```

그렇다고해서 snprintf도 안전하지는 않습니다. 그 이유는 snprintf 함수는 포맷스트링이 됐을 때 문자열의 최종 길이를 반환합니다. 

```c
#include <stdio.h>

int main(){
        char buf[8];
        printf("ret : %d\n",snprintf(buf,sizeof(buf),"AAAA%s","BBBBBBBBBBBBBBBBBB"));
        printf("%s\n",buf);
}
```

```
$ ./snprintf_test
ret : 22
AAAABBB
```

- cve-2018-18820

실제로 [xiph.org](http://xiph.org) 재단이 관리하는 오픈 소스 스트리밍 미디어 서버 [icecast.org](https://www.icecast.org/)의 취약점이 발생했습니다. 해당 취약점은 2.4.4 이전에 icecast의 URL 백엔드에서 BOF가 발생합니다. 공격자는 HTTP Header를 조작해 특정 리소스에 대한 요청을 보내 서비스 거부 및 RCE를 초래할 수 있습니다.

아래는 icecase의 `CVE-2018-18820` 취약점을 간단하게 나타낸 코드입니다. 이 코드에서는 Current HTTP header를 post에 복사할 때 사용됩니다. snprintf를 이용해서 post_offset에 계속 더해주는데 해당 변수의 경계가 없어 취약점이 발생합니다.

```c
post_offset += snprintf(post + post_offset,
                        sizeof(post) - post_offset,
                        "%s",
                        cur_header);
```

결과적으로 snprintf함수로 인해 원하는만큼 많은 데이터를 효과적으로 쓸 수 있습니다. 해당 데이터는 버퍼 post + post_offset 끝을 넘어서에 쓰여지고 post스택의 다른 내용을 덮어 쓸 수 있게됩니다.

![Untitled](https://github.com/realsung/VulnFinder-CodeQL/assets/32904385/8693a018-7dbf-42b5-a4a6-05b4664c664e)


하나의 긴 HTTP Header를 요청해 잘릴 수도 있지만 우리는 post_offset을 이용해서 원하는 스택의 위치에 배치할 수 있다. 그렇게 배치한 후에 HTTP Header를 보낼 수도 있다.

![Untitled](https://github.com/realsung/VulnFinder-CodeQL/assets/32904385/36e31a54-8dbf-43c1-8aa6-e28b8edadfd6)


공격자에게 한 가지 어려운 점이 있다면 snprintf는 Header를 복사하기 전에 Header를 삭제하므로 스택에 쓸 수있는 데이터가 다소 제한되어 있다는 것입니다. 그래도 segment fault가 발생시킬 수 있습니다. 악의의 목적을 가지고 공격을 한다면 RCE까지 도달할 수도 있을 것입니다.

- Patch

해당 취약점에 대한 패치가 되었는데 매우 간단하다. left, ret이라는 변수를 추가해서 반환 값에 대한  경계 검사를 한다.

```c
size_t left = sizeof(post) - post_offset;

ret = snprintf(post + post_offset,
			    sizeof(post) - post_offset,
			    "&%s%s=%s",
			    cur_header, header_valesc);

if (ret <= 0 || (size_t)ret >= left) {
    ICECAST_LOG_ERROR("Authentication failed for client %p as header \"%H\" is too long.", client, cur_header);
    free(pass_headers);
    auth_user_url_clear(auth_user);
    return AUTH_FAILED;
} else {
    post_offset += ret;
}
```

### codeQL Query 분석

- Query 1

첫 번째 쿼리는 호출하는 함수 이름이 snprintf면 함수 call과 경고 문구를 반환한다.

```codeql
import cpp // QL Library import 

from FunctionCall call // get FunctionCall type call
where call.getTarget().getName() = "snprintf"  // if getName() == "snprintf"
select call, "potentially dangerous call to snprintf." // abort message
```

- Query 2

첫 번째 쿼리와 다르게 and call 구문이 추가되었다. 새로운 구문을 보면 2번째 인자의 값을 가져와서 정규식으로 %s가 포함되면 함수 call과 경고 문구를 반환한다.

```codeql
from FunctionCall call
where call.getTarget().getName() = "snprintf"
  and call.getArgument(2).getValue().regexpMatch("(?s).*%s.*")
select call, "potentially dangerous snprintf."
```

- Query 3

앞서 본 2번째 쿼리에서 and TaintTracking이라는 구문이 더 추가되었다. 

Taint Analysis는 데이터 플로우 기법을 이용해 snprintf의 리턴 값이 snprintf의 첫 번째 인자로 전달되는 call을 찾아준다. 이렇게 해서 실행 플로우에 영향이 가는 것을 분석해주는 것이다.

```codeql
import semmle.code.cpp.dataflow.TaintTracking

from FunctionCall call
where call.getTarget().getName() = "snprintf"
  and call.getArgument(2).getValue().regexpMatch("(?s).*%s.*")
  and TaintTracking::localTaint(DataFlow::exprNode(call), DataFlow::exprNode(call.getArgument(1)))
select call, "potentially dangerous call to snprintf."
```

- if + snprintf

3번째 쿼리의 미흡한 점으로 인해 아래 코드가 오탐지가 났다. 반환 값에 대한 검사이외의  `if (offset + len + 1 >= option_str_len){break;}` 으로 예외처리를 하고 있으므로 오탐을 하게된다

```c
while (token != NULL) {
        if (strncmp(token, search_str, search_str_len) == 0) {
                token = strtok(NULL, "&");
                continue;
        }
        int len = strlen(token);
        if (offset + len + 1 >= option_str_len) {
                break;
        }
        int bytes = snprintf((char*)option_str + offset,
                        (option_str_len - offset), "%s&", token);
        if (bytes <= 0) {
                break;
        }
        offset += bytes;
        token = strtok(NULL, "&");
}
```

- Query 4

위의 if문을 생각해 오탐지를 해결하기 위해 쿼리 4를 짤 수 있다.

```codeql
import cpp
import semmle.code.cpp.dataflow.TaintTracking
import semmle.code.cpp.controlflow.Guards

from FunctionCall call
where call.getTarget().getName() = "snprintf"
  and call.getArgument(2).getValue().regexpMatch("(?s).*%s.*")
  and TaintTracking::localTaint(DataFlow::exprNode(call), DataFlow::exprNode(call.getArgument(1)))
  // Exclude cases where it seems there is a check in place
  and not exists(GuardCondition guard, Expr operand |
      // Whether or not call is called is controlled by this guard 
      guard.controls(call.getBasicBlock(), _) and
      // operand is one of the values compared in the guard
      guard.(ComparisonOperation).getAnOperand() = operand and
      // the operand is derrived from the return value of the call to snprintf 
      TaintTracking::localTaint(DataFlow::exprNode(call), DataFlow::exprNode(operand))
  )
select call
```

새로 추가된 쿼리들을 확인해보면 아래와 같다. guard check로 리턴 값이 사용되고 비교연산에 사용되고 조건문에 들어간다면 취약하다고 제어해준다. 

```codeql
import semmle.code.cpp.controlflow.Guards // GuardCondition을 사용하기 위해 import

  and not exists(GuardCondition guard, Expr operand |
      // Whether or not call is called is controlled by this guard 
      guard.controls(call.getBasicBlock(), _) and
      // operand is one of the values compared in the guard
      guard.(ComparisonOperation).getAnOperand() = operand and
      // the operand is derrived from the return value of the call to snprintf 
      TaintTracking::localTaint(DataFlow::exprNode(call), DataFlow::exprNode(operand))
```

이를 통해서 3번 쿼리로는 찾지 못하는 취약점을 4번 쿼리로  `CVE-2018-1000140` 취약점을 찾아낼 수 있었습니다. iAllNames += 해주고 만약 `-iAllNames > sizeof(allNames)` 일 때 `sizeof(allNames)-iAllNames` 을 하면 snprintf가 overflow가 발생하게 됩니다.

```c
iAllNames += snprintf(allNames+iAllNames, sizeof(allNames)-iAllNames,
                      "DNSname: %s; ", szAltName);
```

Reference

https://securitylab.github.com/research/cve-2018-18820-snprintf-vulnerability-icecast

[https://blog.semmle.com/introduction-to-variant-analysis-part-2](https://blog.semmle.com/introduction-to-variant-analysis-part-2/)

https://securitylab.github.com/research/librelp-buffer-overflow-cve-2018-1000140
