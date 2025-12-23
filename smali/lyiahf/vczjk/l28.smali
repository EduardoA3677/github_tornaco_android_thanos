.class public final Llyiahf/vczjk/l28;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $label:Ljava/lang/String;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/h48;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h48;Ljava/lang/String;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/l28;->this$0:Llyiahf/vczjk/h48;

    iput-object p2, p0, Llyiahf/vczjk/l28;->$label:Ljava/lang/String;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 2

    new-instance p1, Llyiahf/vczjk/l28;

    iget-object v0, p0, Llyiahf/vczjk/l28;->this$0:Llyiahf/vczjk/h48;

    iget-object v1, p0, Llyiahf/vczjk/l28;->$label:Ljava/lang/String;

    invoke-direct {p1, v0, v1, p2}, Llyiahf/vczjk/l28;-><init>(Llyiahf/vczjk/h48;Ljava/lang/String;Llyiahf/vczjk/yo1;)V

    return-object p1
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/l28;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/l28;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/l28;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/l28;->label:I

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v3, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v3, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/l28;->this$0:Llyiahf/vczjk/h48;

    iget-object p1, p1, Llyiahf/vczjk/h48;->OooO0o:Llyiahf/vczjk/e28;

    invoke-static {}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;->newBuilder()Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet$Builder;

    move-result-object v1

    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    move-result-object v4

    new-instance v5, Ljava/lang/StringBuilder;

    const-string v6, "User-"

    invoke-direct {v5, v6}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v4

    invoke-virtual {v1, v4}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet$Builder;->setId(Ljava/lang/String;)Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet$Builder;

    move-result-object v1

    iget-object v4, p0, Llyiahf/vczjk/l28;->$label:Ljava/lang/String;

    invoke-virtual {v1, v4}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet$Builder;->setLabel(Ljava/lang/String;)Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet$Builder;

    move-result-object v1

    invoke-virtual {v1}, Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet$Builder;->build()Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;

    move-result-object v1

    const-string v4, "build(...)"

    invoke-static {v1, v4}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    iput v3, p0, Llyiahf/vczjk/l28;->label:I

    iget-object p1, p1, Llyiahf/vczjk/e28;->OooO00o:Llyiahf/vczjk/u18;

    iget-object p1, p1, Llyiahf/vczjk/u18;->OooO00o:Landroid/content/Context;

    invoke-static {p1}, Llyiahf/vczjk/mw6;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p1

    new-instance v3, Llyiahf/vczjk/w08;

    const/4 v4, 0x0

    invoke-direct {v3, v1, v4}, Llyiahf/vczjk/w08;-><init>(Ltornaco/apps/thanox/core/proto/common/SmartFreezePkgSet;Llyiahf/vczjk/yo1;)V

    invoke-interface {p1, v3, p0}, Llyiahf/vczjk/ay1;->OooO00o(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_2

    goto :goto_0

    :cond_2
    move-object p1, v2

    :goto_0
    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    move-object p1, v2

    :goto_1
    if-ne p1, v0, :cond_4

    return-object v0

    :cond_4
    return-object v2
.end method
