.class public final Llyiahf/vczjk/q43;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/bf3;

.field public final synthetic OooOOO0:Llyiahf/vczjk/hl7;

.field public final synthetic OooOOOO:Llyiahf/vczjk/h43;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/hl7;Llyiahf/vczjk/bf3;Llyiahf/vczjk/h43;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q43;->OooOOO0:Llyiahf/vczjk/hl7;

    iput-object p2, p0, Llyiahf/vczjk/q43;->OooOOO:Llyiahf/vczjk/bf3;

    iput-object p3, p0, Llyiahf/vczjk/q43;->OooOOOO:Llyiahf/vczjk/h43;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 7

    instance-of v0, p2, Llyiahf/vczjk/p43;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/p43;

    iget v1, v0, Llyiahf/vczjk/p43;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/p43;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/p43;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/p43;-><init>(Llyiahf/vczjk/q43;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/p43;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/p43;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v4, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_4

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object p1, v0, Llyiahf/vczjk/p43;->L$1:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/hl7;

    iget-object v2, v0, Llyiahf/vczjk/p43;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/q43;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/q43;->OooOOO0:Llyiahf/vczjk/hl7;

    iget-object v2, p2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    sget-object v5, Llyiahf/vczjk/sb;->OooO0OO:Ljava/lang/Object;

    if-ne v2, v5, :cond_4

    move-object v2, p0

    goto :goto_2

    :cond_4
    iput-object p0, v0, Llyiahf/vczjk/p43;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/p43;->L$1:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/p43;->label:I

    iget-object v4, p0, Llyiahf/vczjk/q43;->OooOOO:Llyiahf/vczjk/bf3;

    invoke-interface {v4, v2, p1, v0}, Llyiahf/vczjk/bf3;->OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_5

    goto :goto_3

    :cond_5
    move-object v2, p2

    move-object p2, p1

    move-object p1, v2

    move-object v2, p0

    :goto_1
    move-object v6, p2

    move-object p2, p1

    move-object p1, v6

    :goto_2
    iput-object p1, p2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    iget-object p1, v2, Llyiahf/vczjk/q43;->OooOOOO:Llyiahf/vczjk/h43;

    iget-object p2, v2, Llyiahf/vczjk/q43;->OooOOO0:Llyiahf/vczjk/hl7;

    iget-object p2, p2, Llyiahf/vczjk/hl7;->element:Ljava/lang/Object;

    const/4 v2, 0x0

    iput-object v2, v0, Llyiahf/vczjk/p43;->L$0:Ljava/lang/Object;

    iput-object v2, v0, Llyiahf/vczjk/p43;->L$1:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/p43;->label:I

    invoke-interface {p1, p2, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_6

    :goto_3
    return-object v1

    :cond_6
    :goto_4
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
