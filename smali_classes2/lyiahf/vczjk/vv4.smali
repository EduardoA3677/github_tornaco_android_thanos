.class public final Llyiahf/vczjk/vv4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/xv4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/xv4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/vv4;->this$0:Llyiahf/vczjk/xv4;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 8

    iget-object v0, p0, Llyiahf/vczjk/vv4;->this$0:Llyiahf/vczjk/xv4;

    iget-object v0, v0, Llyiahf/vczjk/xv4;->OooO00o:Llyiahf/vczjk/dw4;

    invoke-virtual {v0}, Llyiahf/vczjk/dw4;->OooO0oO()Llyiahf/vczjk/sv4;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/sv4;->OooOO0O:Ljava/lang/Object;

    invoke-static {v0}, Llyiahf/vczjk/d21;->Oooooo(Ljava/lang/Iterable;)Llyiahf/vczjk/vy;

    move-result-object v0

    sget-object v1, Llyiahf/vczjk/wv4;->OooOOO:Llyiahf/vczjk/wv4;

    invoke-static {v0, v1}, Llyiahf/vczjk/ag8;->Oooo0oo(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/jy9;

    move-result-object v0

    iget-object v1, p0, Llyiahf/vczjk/vv4;->this$0:Llyiahf/vczjk/xv4;

    iget-object v2, v0, Llyiahf/vczjk/jy9;->OooO00o:Llyiahf/vczjk/wf8;

    invoke-interface {v2}, Llyiahf/vczjk/wf8;->iterator()Ljava/util/Iterator;

    move-result-object v2

    const/4 v3, 0x0

    :cond_0
    :goto_0
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    move-result v4

    if-eqz v4, :cond_1

    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object v4

    iget-object v5, v0, Llyiahf/vczjk/jy9;->OooO0O0:Llyiahf/vczjk/oe3;

    invoke-interface {v5, v4}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v4

    move-object v5, v4

    check-cast v5, Llyiahf/vczjk/yv4;

    iget-object v6, v5, Llyiahf/vczjk/yv4;->OooO00o:Llyiahf/vczjk/gv4;

    check-cast v6, Llyiahf/vczjk/tv4;

    iget v6, v6, Llyiahf/vczjk/tv4;->OooOOOo:I

    iget-object v7, v1, Llyiahf/vczjk/xv4;->OooO0O0:Llyiahf/vczjk/ze3;

    invoke-interface {v7, v1, v5}, Llyiahf/vczjk/ze3;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v5

    check-cast v5, Ljava/lang/Number;

    invoke-virtual {v5}, Ljava/lang/Number;->intValue()I

    move-result v5

    if-gt v6, v5, :cond_0

    move-object v3, v4

    goto :goto_0

    :cond_1
    check-cast v3, Llyiahf/vczjk/yv4;

    return-object v3
.end method
