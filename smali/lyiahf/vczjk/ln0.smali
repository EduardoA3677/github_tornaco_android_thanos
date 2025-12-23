.class public final Llyiahf/vczjk/ln0;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO0:Llyiahf/vczjk/h43;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/h43;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/ln0;->OooOOO0:Llyiahf/vczjk/h43;

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 7

    instance-of v0, p2, Llyiahf/vczjk/kn0;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/kn0;

    iget v1, v0, Llyiahf/vczjk/kn0;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/kn0;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/kn0;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/kn0;-><init>(Llyiahf/vczjk/ln0;Llyiahf/vczjk/yo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/kn0;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/kn0;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    check-cast p1, Llyiahf/vczjk/yq5;

    new-instance p2, Llyiahf/vczjk/xm6;

    iget-object v2, p1, Llyiahf/vczjk/yq5;->OooO0O0:Llyiahf/vczjk/jn0;

    iget-object v2, v2, Llyiahf/vczjk/jn0;->OooO0o0:Llyiahf/vczjk/s48;

    new-instance v4, Llyiahf/vczjk/vq5;

    const/4 v5, 0x0

    invoke-direct {v4, p1, v5}, Llyiahf/vczjk/vq5;-><init>(Llyiahf/vczjk/yq5;Llyiahf/vczjk/yo1;)V

    new-instance v6, Llyiahf/vczjk/l53;

    invoke-direct {v6, v2, v4}, Llyiahf/vczjk/l53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/ze3;)V

    new-instance v2, Llyiahf/vczjk/wq5;

    invoke-direct {v2, p1, v5}, Llyiahf/vczjk/wq5;-><init>(Llyiahf/vczjk/yq5;Llyiahf/vczjk/yo1;)V

    new-instance v4, Llyiahf/vczjk/j53;

    invoke-direct {v4, v6, v2}, Llyiahf/vczjk/j53;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/bf3;)V

    iget-object v2, p1, Llyiahf/vczjk/yq5;->OooO00o:Llyiahf/vczjk/xm6;

    iget-object v5, v2, Llyiahf/vczjk/xm6;->OooO0O0:Llyiahf/vczjk/a27;

    new-instance v6, Llyiahf/vczjk/xq5;

    invoke-direct {v6, p1}, Llyiahf/vczjk/xq5;-><init>(Llyiahf/vczjk/yq5;)V

    iget-object p1, v2, Llyiahf/vczjk/xm6;->OooO0OO:Llyiahf/vczjk/ni6;

    invoke-direct {p2, v4, v5, p1, v6}, Llyiahf/vczjk/xm6;-><init>(Llyiahf/vczjk/f43;Llyiahf/vczjk/a27;Llyiahf/vczjk/ni6;Llyiahf/vczjk/le3;)V

    iput v3, v0, Llyiahf/vczjk/kn0;->label:I

    iget-object p1, p0, Llyiahf/vczjk/ln0;->OooOOO0:Llyiahf/vczjk/h43;

    invoke-interface {p1, p2, v0}, Llyiahf/vczjk/h43;->emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p1

    if-ne p1, v1, :cond_3

    return-object v1

    :cond_3
    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
