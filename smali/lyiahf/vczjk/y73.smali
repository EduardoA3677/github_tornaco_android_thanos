.class public final Llyiahf/vczjk/y73;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Landroidx/work/impl/WorkDatabase_Impl;

.field public final synthetic OooOOO0:Llyiahf/vczjk/h43;

.field public final synthetic OooOOOO:Llyiahf/vczjk/o000OO;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h43;Landroidx/work/impl/WorkDatabase_Impl;Llyiahf/vczjk/o000OO;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/y73;->OooOOO0:Llyiahf/vczjk/h43;

    iput-object p2, p0, Llyiahf/vczjk/y73;->OooOOO:Landroidx/work/impl/WorkDatabase_Impl;

    iput-object p3, p0, Llyiahf/vczjk/y73;->OooOOOO:Llyiahf/vczjk/o000OO;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 5

    instance-of v0, p2, Llyiahf/vczjk/x73;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/x73;

    iget v1, v0, Llyiahf/vczjk/x73;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/x73;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/x73;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/x73;-><init>(Llyiahf/vczjk/y73;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/x73;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/x73;->label:I

    const/4 v3, 0x2

    const/4 v4, 0x1

    if-eqz v2, :cond_3

    if-eq v2, v4, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_3

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    iget-object p1, v0, Llyiahf/vczjk/x73;->L$0:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/h43;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_3
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    check-cast p1, Ljava/util/Set;

    iget-object p1, p0, Llyiahf/vczjk/y73;->OooOOO0:Llyiahf/vczjk/h43;

    iput-object p1, v0, Llyiahf/vczjk/x73;->L$0:Ljava/lang/Object;

    iput v4, v0, Llyiahf/vczjk/x73;->label:I

    iget-object p2, p0, Llyiahf/vczjk/y73;->OooOOO:Landroidx/work/impl/WorkDatabase_Impl;

    iget-object v2, p0, Llyiahf/vczjk/y73;->OooOOOO:Llyiahf/vczjk/o000OO;

    invoke-static {p2, v4, v2, v0}, Llyiahf/vczjk/u34;->OoooO0(Landroidx/work/impl/WorkDatabase_Impl;ZLlyiahf/vczjk/o000OO;Llyiahf/vczjk/zo1;)Ljava/lang/Object;

    move-result-object p2

    if-ne p2, v1, :cond_4

    goto :goto_2

    :cond_4
    :goto_1
    const/4 v2, 0x0

    iput-object v2, v0, Llyiahf/vczjk/x73;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/x73;->label:I

    invoke-interface {p1, p2, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_5

    :goto_2
    return-object v1

    :cond_5
    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
