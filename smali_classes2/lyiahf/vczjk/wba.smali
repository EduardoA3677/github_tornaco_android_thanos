.class public final Llyiahf/vczjk/wba;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $code:Ljava/lang/String;

.field final synthetic $deviceId:Ljava/lang/String;

.field final synthetic $onError:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic $onSuccess:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field private synthetic L$0:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/wba;->$code:Ljava/lang/String;

    iput-object p2, p0, Llyiahf/vczjk/wba;->$deviceId:Ljava/lang/String;

    iput-object p3, p0, Llyiahf/vczjk/wba;->$onSuccess:Llyiahf/vczjk/oe3;

    iput-object p4, p0, Llyiahf/vczjk/wba;->$onError:Llyiahf/vczjk/oe3;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/wba;

    iget-object v1, p0, Llyiahf/vczjk/wba;->$code:Ljava/lang/String;

    iget-object v2, p0, Llyiahf/vczjk/wba;->$deviceId:Ljava/lang/String;

    iget-object v3, p0, Llyiahf/vczjk/wba;->$onSuccess:Llyiahf/vczjk/oe3;

    iget-object v4, p0, Llyiahf/vczjk/wba;->$onError:Llyiahf/vczjk/oe3;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/wba;-><init>(Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;Llyiahf/vczjk/yo1;)V

    iput-object p1, v0, Llyiahf/vczjk/wba;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/wba;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/wba;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/wba;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v0, p0, Llyiahf/vczjk/wba;->label:I

    if-nez v0, :cond_8

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/wba;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/xr1;

    iget-object p1, p0, Llyiahf/vczjk/wba;->$code:Ljava/lang/String;

    iget-object v0, p0, Llyiahf/vczjk/wba;->$deviceId:Ljava/lang/String;

    iget-object v1, p0, Llyiahf/vczjk/wba;->$onSuccess:Llyiahf/vczjk/oe3;

    :try_start_0
    sget-object v2, Llyiahf/vczjk/xba;->OooO0OO:Llyiahf/vczjk/sc9;

    invoke-virtual {v2}, Llyiahf/vczjk/sc9;->getValue()Ljava/lang/Object;

    move-result-object v2

    const-string v3, "getValue(...)"

    invoke-static {v2, v3}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast v2, Llyiahf/vczjk/cp;

    invoke-interface {v2, p1, v0}, Llyiahf/vczjk/cp;->OooO00o(Ljava/lang/String;Ljava/lang/String;)Llyiahf/vczjk/wn0;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/wn0;->OooO0o()Llyiahf/vczjk/hs7;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/hs7;->OooO0O0:Ljava/lang/Object;

    check-cast p1, Lgithub/tornaco/android/thanos/core/CommonApiResWrapper;

    invoke-static {p1}, Ljava/util/Objects;->toString(Ljava/lang/Object;)Ljava/lang/String;

    if-eqz p1, :cond_6

    invoke-static {}, Ltornaco/apps/thanox/core/proto/common/CommonApiRes;->newBuilder()Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;

    move-result-object v0

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/CommonApiResWrapper;->getResult()I

    move-result v2

    invoke-virtual {v0, v2}, Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;->setResult(I)Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;

    move-result-object v0

    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/CommonApiResWrapper;->getMsg()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_0

    invoke-virtual {v0, v2}, Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;->setMsg(Ljava/lang/String;)Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;

    goto :goto_0

    :catchall_0
    move-exception p1

    goto :goto_1

    :cond_0
    :goto_0
    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/CommonApiResWrapper;->getK()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_1

    invoke-virtual {v0, v2}, Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;->setK(Ljava/lang/String;)Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;

    :cond_1
    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/CommonApiResWrapper;->getI()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_2

    invoke-virtual {v0, v2}, Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;->setI(Ljava/lang/String;)Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;

    :cond_2
    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/CommonApiResWrapper;->getJ()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_3

    invoke-virtual {v0, v2}, Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;->setJ(Ljava/lang/String;)Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;

    :cond_3
    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/CommonApiResWrapper;->getL()Ljava/lang/String;

    move-result-object v2

    if-eqz v2, :cond_4

    invoke-virtual {v0, v2}, Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;->setL(Ljava/lang/String;)Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;

    :cond_4
    invoke-virtual {p1}, Lgithub/tornaco/android/thanos/core/CommonApiResWrapper;->getM()Ljava/lang/String;

    move-result-object p1

    if-eqz p1, :cond_5

    invoke-virtual {v0, p1}, Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;->setM(Ljava/lang/String;)Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;

    :cond_5
    invoke-virtual {v0}, Ltornaco/apps/thanox/core/proto/common/CommonApiRes$Builder;->build()Ltornaco/apps/thanox/core/proto/common/CommonApiRes;

    move-result-object p1

    const-string v0, "build(...)"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-interface {v1, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    goto :goto_2

    :cond_6
    const/4 p1, 0x0

    goto :goto_2

    :goto_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooO0oo(Ljava/lang/Throwable;)Llyiahf/vczjk/ts7;

    move-result-object p1

    :goto_2
    iget-object v0, p0, Llyiahf/vczjk/wba;->$onError:Llyiahf/vczjk/oe3;

    invoke-static {p1}, Llyiahf/vczjk/vs7;->OooO00o(Ljava/lang/Object;)Ljava/lang/Throwable;

    move-result-object v1

    if-eqz v1, :cond_7

    invoke-interface {v0, v1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    sget v0, Llyiahf/vczjk/xba;->OooO0O0:I

    add-int/lit8 v0, v0, 0x1

    sput v0, Llyiahf/vczjk/xba;->OooO0O0:I

    :cond_7
    new-instance v0, Llyiahf/vczjk/vs7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/vs7;-><init>(Ljava/lang/Object;)V

    return-object v0

    :cond_8
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
