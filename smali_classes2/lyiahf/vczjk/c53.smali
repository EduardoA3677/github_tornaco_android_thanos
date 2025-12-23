.class public final Llyiahf/vczjk/c53;
.super Llyiahf/vczjk/eb9;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic $downstream:Llyiahf/vczjk/h43;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/h43;"
        }
    .end annotation
.end field

.field final synthetic $lastValue:Llyiahf/vczjk/hl7;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/hl7;"
        }
    .end annotation
.end field

.field synthetic L$0:Ljava/lang/Object;

.field L$1:Ljava/lang/Object;

.field label:I


# direct methods
.method public constructor <init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/hl7;)V
    .locals 0

    iput-object p3, p0, Llyiahf/vczjk/c53;->$lastValue:Llyiahf/vczjk/hl7;

    iput-object p2, p0, Llyiahf/vczjk/c53;->$downstream:Llyiahf/vczjk/h43;

    const/4 p2, 0x2

    invoke-direct {p0, p2, p1}, Llyiahf/vczjk/eb9;-><init>(ILlyiahf/vczjk/yo1;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;
    .locals 3

    new-instance v0, Llyiahf/vczjk/c53;

    iget-object v1, p0, Llyiahf/vczjk/c53;->$lastValue:Llyiahf/vczjk/hl7;

    iget-object v2, p0, Llyiahf/vczjk/c53;->$downstream:Llyiahf/vczjk/h43;

    invoke-direct {v0, p2, v2, v1}, Llyiahf/vczjk/c53;-><init>(Llyiahf/vczjk/yo1;Llyiahf/vczjk/h43;Llyiahf/vczjk/hl7;)V

    iput-object p1, v0, Llyiahf/vczjk/c53;->L$0:Ljava/lang/Object;

    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    check-cast p1, Llyiahf/vczjk/jt0;

    iget-object p1, p1, Llyiahf/vczjk/jt0;->OooO00o:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/yo1;

    new-instance v0, Llyiahf/vczjk/jt0;

    invoke-direct {v0, p1}, Llyiahf/vczjk/jt0;-><init>(Ljava/lang/Object;)V

    invoke-virtual {p0, v0, p2}, Llyiahf/vczjk/c53;->create(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Llyiahf/vczjk/yo1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c53;

    sget-object p2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/c53;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    return-object p1
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 7

    sget-object v0, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, p0, Llyiahf/vczjk/c53;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_1

    if-ne v1, v2, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/c53;->L$1:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/hl7;

    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_0
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_1
    invoke-static {p1}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/c53;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/jt0;

    iget-object p1, p1, Llyiahf/vczjk/jt0;->OooO00o:Ljava/lang/Object;

    iget-object v1, p0, Llyiahf/vczjk/c53;->$lastValue:Llyiahf/vczjk/hl7;

    instance-of v3, p1, Llyiahf/vczjk/it0;

    if-nez v3, :cond_2

    iput-object p1, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    :cond_2
    iget-object v4, p0, Llyiahf/vczjk/c53;->$downstream:Llyiahf/vczjk/h43;

    if-eqz v3, :cond_9

    instance-of v3, p1, Llyiahf/vczjk/ht0;

    const/4 v5, 0x0

    if-eqz v3, :cond_3

    move-object v3, p1

    check-cast v3, Llyiahf/vczjk/ht0;

    goto :goto_0

    :cond_3
    move-object v3, v5

    :goto_0
    if-eqz v3, :cond_4

    iget-object v3, v3, Llyiahf/vczjk/ht0;->OooO00o:Ljava/lang/Throwable;

    goto :goto_1

    :cond_4
    move-object v3, v5

    :goto_1
    if-nez v3, :cond_8

    iget-object v3, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    if-eqz v3, :cond_7

    sget-object v6, Llyiahf/vczjk/bua;->OooO0Oo:Llyiahf/vczjk/h87;

    if-ne v3, v6, :cond_5

    goto :goto_2

    :cond_5
    move-object v5, v3

    :goto_2
    iput-object p1, p0, Llyiahf/vczjk/c53;->L$0:Ljava/lang/Object;

    iput-object v1, p0, Llyiahf/vczjk/c53;->L$1:Ljava/lang/Object;

    iput v2, p0, Llyiahf/vczjk/c53;->label:I

    invoke-interface {v4, v5, p0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v0, :cond_6

    return-object v0

    :cond_6
    move-object v0, v1

    :goto_3
    move-object v1, v0

    :cond_7
    sget-object p1, Llyiahf/vczjk/bua;->OooO0o:Llyiahf/vczjk/h87;

    iput-object p1, v1, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    goto :goto_4

    :cond_8
    throw v3

    :cond_9
    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
