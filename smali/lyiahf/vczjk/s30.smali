.class public final Llyiahf/vczjk/s30;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $props:Ljava/util/List;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field final synthetic $start:J

.field L$0:Ljava/lang/Object;

.field label:I

.field final synthetic this$0:Llyiahf/vczjk/i40;


# direct methods
.method public constructor <init>(Ljava/util/List;JLlyiahf/vczjk/i40;Llyiahf/vczjk/yo1;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/s30;->$props:Ljava/util/List;

    iput-wide p2, p0, Llyiahf/vczjk/s30;->$start:J

    iput-object p4, p0, Llyiahf/vczjk/s30;->this$0:Llyiahf/vczjk/i40;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p5}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 6

    new-instance v0, Llyiahf/vczjk/s30;

    iget-object v1, p0, Llyiahf/vczjk/s30;->$props:Ljava/util/List;

    iget-wide v2, p0, Llyiahf/vczjk/s30;->$start:J

    iget-object v4, p0, Llyiahf/vczjk/s30;->this$0:Llyiahf/vczjk/i40;

    move-object v5, p2

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/s30;-><init>(Ljava/util/List;JLlyiahf/vczjk/i40;Llyiahf/vczjk/yo1;)V

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    check-cast p1, Llyiahf/vczjk/xr1;

    check-cast p2, Llyiahf/vczjk/yo1;

    invoke-virtual {p0, p1, p2}, Llyiahf/vczjk/s30;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/s30;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/s30;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/s30;->label:I

    const/4 v2, 0x2

    const/4 v3, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v3, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/s30;->L$0:Ljava/lang/Object;

    check-cast v0, Ljava/util/List;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_2

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_0

    :cond_2
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/km8;->OooO00o:Llyiahf/vczjk/km8;

    iput v3, p0, Llyiahf/vczjk/s30;->label:I

    invoke-virtual {p1, p0}, Llyiahf/vczjk/km8;->OooO0O0(Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_3

    goto :goto_1

    :cond_3
    :goto_0
    check-cast p1, Lgithub/tornaco/android/thanos/core/IThanosLite;

    invoke-static {}, Ltornaco/apps/thanox/core/proto/common/RequestPayload;->newBuilder()Ltornaco/apps/thanox/core/proto/common/RequestPayload$Builder;

    move-result-object v1

    iget-object v3, p0, Llyiahf/vczjk/s30;->$props:Ljava/util/List;

    invoke-virtual {v1, v3}, Ltornaco/apps/thanox/core/proto/common/RequestPayload$Builder;->addAllData(Ljava/lang/Iterable;)Ltornaco/apps/thanox/core/proto/common/RequestPayload$Builder;

    move-result-object v1

    invoke-virtual {v1}, Ltornaco/apps/thanox/core/proto/common/RequestPayload$Builder;->build()Ltornaco/apps/thanox/core/proto/common/RequestPayload;

    move-result-object v1

    invoke-virtual {v1}, Lcom/google/protobuf/AbstractMessageLite;->toByteArray()[B

    move-result-object v1

    invoke-interface {p1, v1}, Lgithub/tornaco/android/thanos/core/IThanosLite;->getAllPkgs([B)Ljava/util/List;

    move-result-object p1

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v3

    iget-wide v5, p0, Llyiahf/vczjk/s30;->$start:J

    sub-long/2addr v3, v5

    iput-object p1, p0, Llyiahf/vczjk/s30;->L$0:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/s30;->label:I

    invoke-static {v3, v4, p0}, Llyiahf/vczjk/v34;->OooOOOO(JLlyiahf/vczjk/eb9;)Ljava/lang/Object;

    move-result-object v1

    if-ne v1, v0, :cond_4

    :goto_1
    return-object v0

    :cond_4
    move-object v0, p1

    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/s30;->this$0:Llyiahf/vczjk/i40;

    iget-object p1, p1, Llyiahf/vczjk/i40;->OooO0oO:Llyiahf/vczjk/s29;

    :cond_5
    invoke-virtual {p1}, Llyiahf/vczjk/s29;->getValue()Ljava/lang/Object;

    move-result-object v1

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/q30;

    invoke-static {v0}, Llyiahf/vczjk/v34;->OooOo0o(Ljava/lang/Object;)V

    const/16 v3, 0x1e

    const/4 v4, 0x0

    invoke-static {v2, v0, v4, v4, v3}, Llyiahf/vczjk/q30;->OooO00o(Llyiahf/vczjk/q30;Ljava/util/List;Llyiahf/vczjk/mw;Llyiahf/vczjk/mw;I)Llyiahf/vczjk/q30;

    move-result-object v2

    invoke-virtual {p1, v1, v2}, Llyiahf/vczjk/s29;->OooOOO(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v1

    if-eqz v1, :cond_5

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
