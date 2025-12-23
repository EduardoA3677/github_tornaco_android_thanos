.class public final Llyiahf/vczjk/jx4;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic this$0:Llyiahf/vczjk/lx4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/jx4;->this$0:Llyiahf/vczjk/lx4;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/vv3;

    iget p1, p1, Llyiahf/vczjk/vv3;->OooO00o:I

    iget-object v0, p0, Llyiahf/vczjk/jx4;->this$0:Llyiahf/vczjk/lx4;

    iget-object v0, v0, Llyiahf/vczjk/lx4;->OooOOo:Llyiahf/vczjk/uqa;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    const/4 v1, 0x1

    const/4 v2, 0x5

    const/4 v3, 0x6

    const/4 v4, 0x2

    const/4 v5, 0x7

    if-ne p1, v5, :cond_0

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOoo()Llyiahf/vczjk/mj4;

    goto :goto_0

    :cond_0
    if-ne p1, v4, :cond_1

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOoo()Llyiahf/vczjk/mj4;

    goto :goto_0

    :cond_1
    if-ne p1, v3, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOoo()Llyiahf/vczjk/mj4;

    goto :goto_0

    :cond_2
    if-ne p1, v2, :cond_3

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOoo()Llyiahf/vczjk/mj4;

    goto :goto_0

    :cond_3
    const/4 v6, 0x3

    if-ne p1, v6, :cond_4

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOoo()Llyiahf/vczjk/mj4;

    goto :goto_0

    :cond_4
    const/4 v6, 0x4

    if-ne p1, v6, :cond_5

    invoke-virtual {v0}, Llyiahf/vczjk/uqa;->OooOOoo()Llyiahf/vczjk/mj4;

    goto :goto_0

    :cond_5
    if-ne p1, v1, :cond_6

    goto :goto_0

    :cond_6
    if-nez p1, :cond_c

    :goto_0
    sget-object v6, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    const/4 v7, 0x0

    const-string v8, "focusManager"

    if-ne p1, v3, :cond_8

    iget-object p1, v0, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/l83;

    if-eqz p1, :cond_7

    check-cast p1, Llyiahf/vczjk/r83;

    invoke-virtual {p1, v1}, Llyiahf/vczjk/r83;->OooO0o0(I)Z

    return-object v6

    :cond_7
    invoke-static {v8}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v7

    :cond_8
    if-ne p1, v2, :cond_a

    iget-object p1, v0, Llyiahf/vczjk/uqa;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/l83;

    if-eqz p1, :cond_9

    check-cast p1, Llyiahf/vczjk/r83;

    invoke-virtual {p1, v4}, Llyiahf/vczjk/r83;->OooO0o0(I)Z

    return-object v6

    :cond_9
    invoke-static {v8}, Llyiahf/vczjk/v34;->Ooooooo(Ljava/lang/String;)V

    throw v7

    :cond_a
    if-ne p1, v5, :cond_b

    iget-object p1, v0, Llyiahf/vczjk/uqa;->OooOOO:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/dx8;

    if-eqz p1, :cond_b

    check-cast p1, Llyiahf/vczjk/q52;

    invoke-virtual {p1}, Llyiahf/vczjk/q52;->OooO00o()V

    :cond_b
    return-object v6

    :cond_c
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string v0, "invalid ImeAction"

    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
