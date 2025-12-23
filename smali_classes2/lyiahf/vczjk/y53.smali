.class public final Llyiahf/vczjk/y53;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/h43;

.field public final synthetic OooOOO0:Llyiahf/vczjk/dl7;

.field public final synthetic OooOOOO:Llyiahf/vczjk/eb9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/dl7;Llyiahf/vczjk/h43;Llyiahf/vczjk/ze3;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/y53;->OooOOO0:Llyiahf/vczjk/dl7;

    iput-object p2, p0, Llyiahf/vczjk/y53;->OooOOO:Llyiahf/vczjk/h43;

    check-cast p3, Llyiahf/vczjk/eb9;

    iput-object p3, p0, Llyiahf/vczjk/y53;->OooOOOO:Llyiahf/vczjk/eb9;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 7

    instance-of v0, p2, Llyiahf/vczjk/x53;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/x53;

    iget v1, v0, Llyiahf/vczjk/x53;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/x53;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/x53;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/x53;-><init>(Llyiahf/vczjk/y53;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/x53;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/x53;->label:I

    sget-object v3, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v4, 0x3

    const/4 v5, 0x2

    const/4 v6, 0x1

    if-eqz v2, :cond_4

    if-eq v2, v6, :cond_3

    if-eq v2, v5, :cond_2

    if-ne v2, v4, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v3

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object p1, v0, Llyiahf/vczjk/x53;->L$1:Ljava/lang/Object;

    iget-object v2, v0, Llyiahf/vczjk/x53;->L$0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/y53;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    return-object v3

    :cond_4
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iget-object p2, p0, Llyiahf/vczjk/y53;->OooOOO0:Llyiahf/vczjk/dl7;

    iget-boolean p2, p2, Llyiahf/vczjk/dl7;->element:Z

    if-eqz p2, :cond_5

    iput v6, v0, Llyiahf/vczjk/x53;->label:I

    iget-object p2, p0, Llyiahf/vczjk/y53;->OooOOO:Llyiahf/vczjk/h43;

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_7

    goto :goto_2

    :cond_5
    iput-object p0, v0, Llyiahf/vczjk/x53;->L$0:Ljava/lang/Object;

    iput-object p1, v0, Llyiahf/vczjk/x53;->L$1:Ljava/lang/Object;

    iput v5, v0, Llyiahf/vczjk/x53;->label:I

    iget-object p2, p0, Llyiahf/vczjk/y53;->OooOOOO:Llyiahf/vczjk/eb9;

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_6

    goto :goto_2

    :cond_6
    move-object v2, p0

    :goto_1
    check-cast p2, Ljava/lang/Boolean;

    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p2

    if-nez p2, :cond_7

    iget-object p2, v2, Llyiahf/vczjk/y53;->OooOOO0:Llyiahf/vczjk/dl7;

    iput-boolean v6, p2, Llyiahf/vczjk/dl7;->element:Z

    const/4 p2, 0x0

    iput-object p2, v0, Llyiahf/vczjk/x53;->L$0:Ljava/lang/Object;

    iput-object p2, v0, Llyiahf/vczjk/x53;->L$1:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/x53;->label:I

    iget-object p2, v2, Llyiahf/vczjk/y53;->OooOOO:Llyiahf/vczjk/h43;

    invoke-interface {p2, p1, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_7

    :goto_2
    return-object v1

    :cond_7
    return-object v3
.end method
