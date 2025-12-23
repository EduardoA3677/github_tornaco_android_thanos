.class public abstract Llyiahf/vczjk/sx6;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/l39;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    sget-object v0, Llyiahf/vczjk/o24;->OooOo0O:Llyiahf/vczjk/o24;

    new-instance v1, Llyiahf/vczjk/l39;

    invoke-direct {v1, v0}, Landroidx/compose/runtime/OooO;-><init>(Llyiahf/vczjk/le3;)V

    sput-object v1, Llyiahf/vczjk/sx6;->OooO00o:Llyiahf/vczjk/l39;

    return-void
.end method

.method public static final OooO00o(Llyiahf/vczjk/cx4;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)V
    .locals 4

    instance-of v0, p2, Llyiahf/vczjk/qx6;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/qx6;

    iget v1, v0, Llyiahf/vczjk/qx6;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/qx6;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/qx6;

    invoke-direct {v0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/qx6;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, v0, Llyiahf/vczjk/qx6;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_2

    if-eq v1, v2, :cond_1

    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    move-object p2, p0

    check-cast p2, Llyiahf/vczjk/jl5;

    iget-object p2, p2, Llyiahf/vczjk/jl5;->OooOOO0:Llyiahf/vczjk/jl5;

    iget-boolean p2, p2, Llyiahf/vczjk/jl5;->OooOoO:Z

    if-eqz p2, :cond_4

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0O(Llyiahf/vczjk/l52;)Llyiahf/vczjk/tg6;

    move-result-object p2

    invoke-static {p0}, Llyiahf/vczjk/yi4;->o00oO0o(Llyiahf/vczjk/l52;)Llyiahf/vczjk/ro4;

    move-result-object p0

    iget-object p0, p0, Llyiahf/vczjk/ro4;->Oooo0oO:Llyiahf/vczjk/yg1;

    check-cast p0, Llyiahf/vczjk/os6;

    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v1, Llyiahf/vczjk/sx6;->OooO00o:Llyiahf/vczjk/l39;

    invoke-static {p0, v1}, Llyiahf/vczjk/u34;->OoooO(Llyiahf/vczjk/ps6;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p0

    if-nez p0, :cond_3

    iput v2, v0, Llyiahf/vczjk/qx6;->label:I

    invoke-static {p2, p1, v0}, Llyiahf/vczjk/sx6;->OooO0O0(Llyiahf/vczjk/tg6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)V

    return-void

    :cond_3
    new-instance p0, Ljava/lang/ClassCastException;

    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    throw p0

    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "establishTextInputSession called from an unattached node"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static final OooO0O0(Llyiahf/vczjk/tg6;Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)V
    .locals 4

    instance-of v0, p2, Llyiahf/vczjk/rx6;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/rx6;

    iget v1, v0, Llyiahf/vczjk/rx6;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/rx6;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/rx6;

    invoke-direct {v0, p2}, Llyiahf/vczjk/zo1;-><init>(Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/rx6;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v1, v0, Llyiahf/vczjk/rx6;->label:I

    const/4 v2, 0x1

    if-eqz v1, :cond_3

    if-eq v1, v2, :cond_2

    const/4 p0, 0x2

    if-eq v1, p0, :cond_1

    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0

    :cond_1
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    new-instance p0, Llyiahf/vczjk/k61;

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    throw p0

    :cond_3
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    iput v2, v0, Llyiahf/vczjk/rx6;->label:I

    check-cast p0, Llyiahf/vczjk/xa;

    invoke-virtual {p0, p1, v0}, Llyiahf/vczjk/xa;->Oooo0o0(Llyiahf/vczjk/ze3;Llyiahf/vczjk/zo1;)V

    return-void
.end method
