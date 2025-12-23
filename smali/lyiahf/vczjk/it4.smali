.class public final Llyiahf/vczjk/it4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/kt4;

.field final synthetic this$1:Llyiahf/vczjk/jt4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/kt4;Llyiahf/vczjk/jt4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/it4;->this$0:Llyiahf/vczjk/kt4;

    iput-object p2, p0, Llyiahf/vczjk/it4;->this$1:Llyiahf/vczjk/jt4;

    const/4 p1, 0x2

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 10

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 v0, p2, 0x3

    const/4 v1, 0x2

    const/4 v2, 0x1

    const/4 v3, 0x0

    if-eq v0, v1, :cond_0

    move v0, v2

    goto :goto_0

    :cond_0
    move v0, v3

    :goto_0
    and-int/2addr p2, v2

    move-object v8, p1

    check-cast v8, Llyiahf/vczjk/zf1;

    invoke-virtual {v8, p2, v0}, Llyiahf/vczjk/zf1;->Oooo0OO(IZ)Z

    move-result p1

    if-eqz p1, :cond_6

    iget-object p1, p0, Llyiahf/vczjk/it4;->this$0:Llyiahf/vczjk/kt4;

    iget-object p1, p1, Llyiahf/vczjk/kt4;->OooO0O0:Llyiahf/vczjk/qt4;

    invoke-virtual {p1}, Llyiahf/vczjk/qt4;->OooO00o()Ljava/lang/Object;

    move-result-object p1

    move-object v4, p1

    check-cast v4, Llyiahf/vczjk/nt4;

    iget-object p1, p0, Llyiahf/vczjk/it4;->this$1:Llyiahf/vczjk/jt4;

    iget p1, p1, Llyiahf/vczjk/jt4;->OooO0OO:I

    invoke-interface {v4}, Llyiahf/vczjk/nt4;->OooO00o()I

    move-result p2

    const/4 v0, -0x1

    if-ge p1, p2, :cond_2

    invoke-interface {v4, p1}, Llyiahf/vczjk/nt4;->OooO0O0(I)Ljava/lang/Object;

    move-result-object p2

    iget-object v1, p0, Llyiahf/vczjk/it4;->this$1:Llyiahf/vczjk/jt4;

    iget-object v1, v1, Llyiahf/vczjk/jt4;->OooO00o:Ljava/lang/Object;

    invoke-virtual {p2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    move-result p2

    if-nez p2, :cond_1

    goto :goto_2

    :cond_1
    :goto_1
    move v6, p1

    goto :goto_3

    :cond_2
    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/it4;->this$1:Llyiahf/vczjk/jt4;

    iget-object p1, p1, Llyiahf/vczjk/jt4;->OooO00o:Ljava/lang/Object;

    invoke-interface {v4, p1}, Llyiahf/vczjk/nt4;->OooO0Oo(Ljava/lang/Object;)I

    move-result p1

    if-eq p1, v0, :cond_1

    iget-object p2, p0, Llyiahf/vczjk/it4;->this$1:Llyiahf/vczjk/jt4;

    iput p1, p2, Llyiahf/vczjk/jt4;->OooO0OO:I

    goto :goto_1

    :goto_3
    if-eq v6, v0, :cond_3

    const p1, -0x275cf883

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p1, p0, Llyiahf/vczjk/it4;->this$0:Llyiahf/vczjk/kt4;

    iget-object v5, p1, Llyiahf/vczjk/kt4;->OooO00o:Llyiahf/vczjk/o58;

    iget-object p1, p0, Llyiahf/vczjk/it4;->this$1:Llyiahf/vczjk/jt4;

    iget-object v7, p1, Llyiahf/vczjk/jt4;->OooO00o:Ljava/lang/Object;

    const/4 v9, 0x0

    invoke-static/range {v4 .. v9}, Llyiahf/vczjk/l4a;->OooO0o(Llyiahf/vczjk/nt4;Ljava/lang/Object;ILjava/lang/Object;Llyiahf/vczjk/rf1;I)V

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_4

    :cond_3
    const p1, -0x2759648f

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {v8, v3}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    :goto_4
    iget-object p1, p0, Llyiahf/vczjk/it4;->this$1:Llyiahf/vczjk/jt4;

    iget-object p2, p1, Llyiahf/vczjk/jt4;->OooO00o:Ljava/lang/Object;

    invoke-virtual {v8, p1}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/it4;->this$1:Llyiahf/vczjk/jt4;

    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    if-nez p1, :cond_4

    sget-object p1, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-ne v1, p1, :cond_5

    :cond_4
    new-instance v1, Llyiahf/vczjk/ht4;

    invoke-direct {v1, v0}, Llyiahf/vczjk/ht4;-><init>(Llyiahf/vczjk/jt4;)V

    invoke-virtual {v8, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_5
    check-cast v1, Llyiahf/vczjk/oe3;

    invoke-static {p2, v1, v8}, Llyiahf/vczjk/c6a;->OooOO0o(Ljava/lang/Object;Llyiahf/vczjk/oe3;Llyiahf/vczjk/rf1;)V

    goto :goto_5

    :cond_6
    invoke-virtual {v8}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    :goto_5
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
