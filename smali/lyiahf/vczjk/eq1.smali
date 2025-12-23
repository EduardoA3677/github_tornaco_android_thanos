.class public final Llyiahf/vczjk/eq1;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $enabled:Z

.field final synthetic $manager:Llyiahf/vczjk/mk9;

.field final synthetic $offsetMapping:Llyiahf/vczjk/s86;

.field final synthetic $state:Llyiahf/vczjk/lx4;

.field final synthetic $value:Llyiahf/vczjk/gl9;

.field final synthetic $windowInfo:Llyiahf/vczjk/bna;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/lx4;ZLlyiahf/vczjk/bna;Llyiahf/vczjk/mk9;Llyiahf/vczjk/gl9;Llyiahf/vczjk/s86;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    iput-boolean p2, p0, Llyiahf/vczjk/eq1;->$enabled:Z

    iput-object p3, p0, Llyiahf/vczjk/eq1;->$windowInfo:Llyiahf/vczjk/bna;

    iput-object p4, p0, Llyiahf/vczjk/eq1;->$manager:Llyiahf/vczjk/mk9;

    iput-object p5, p0, Llyiahf/vczjk/eq1;->$value:Llyiahf/vczjk/gl9;

    iput-object p6, p0, Llyiahf/vczjk/eq1;->$offsetMapping:Llyiahf/vczjk/s86;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/xn4;

    iget-object v0, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    iput-object p1, v0, Llyiahf/vczjk/lx4;->OooO0oo:Llyiahf/vczjk/xn4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    iput-object p1, v0, Llyiahf/vczjk/nm9;->OooO0O0:Llyiahf/vczjk/xn4;

    :goto_0
    iget-boolean p1, p0, Llyiahf/vczjk/eq1;->$enabled:Z

    if-eqz p1, :cond_5

    iget-object p1, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {p1}, Llyiahf/vczjk/lx4;->OooO00o()Llyiahf/vczjk/vl3;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/vl3;->OooOOO:Llyiahf/vczjk/vl3;

    const/4 v1, 0x0

    const/4 v2, 0x1

    if-ne p1, v0, :cond_2

    iget-object p1, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    iget-object p1, p1, Llyiahf/vczjk/lx4;->OooOO0o:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/eq1;->$windowInfo:Llyiahf/vczjk/bna;

    check-cast p1, Llyiahf/vczjk/yw4;

    iget-object p1, p1, Llyiahf/vczjk/yw4;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Boolean;

    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p1

    if-eqz p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/eq1;->$manager:Llyiahf/vczjk/mk9;

    invoke-virtual {p1}, Llyiahf/vczjk/mk9;->OooOOo()V

    goto :goto_1

    :cond_1
    iget-object p1, p0, Llyiahf/vczjk/eq1;->$manager:Llyiahf/vczjk/mk9;

    invoke-virtual {p1}, Llyiahf/vczjk/mk9;->OooOOO()V

    :goto_1
    iget-object p1, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v0, p0, Llyiahf/vczjk/eq1;->$manager:Llyiahf/vczjk/mk9;

    invoke-static {v0, v2}, Llyiahf/vczjk/ok6;->OooOoO(Llyiahf/vczjk/mk9;Z)Z

    move-result v0

    iget-object p1, p1, Llyiahf/vczjk/lx4;->OooOOO0:Llyiahf/vczjk/qs5;

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v0, p0, Llyiahf/vczjk/eq1;->$manager:Llyiahf/vczjk/mk9;

    invoke-static {v0, v1}, Llyiahf/vczjk/ok6;->OooOoO(Llyiahf/vczjk/mk9;Z)Z

    move-result v0

    iget-object p1, p1, Llyiahf/vczjk/lx4;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    iget-object p1, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v0, p0, Llyiahf/vczjk/eq1;->$value:Llyiahf/vczjk/gl9;

    iget-wide v2, v0, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v2, v3}, Llyiahf/vczjk/gn9;->OooO0O0(J)Z

    move-result v0

    iget-object p1, p1, Llyiahf/vczjk/lx4;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    goto :goto_2

    :cond_2
    iget-object p1, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {p1}, Llyiahf/vczjk/lx4;->OooO00o()Llyiahf/vczjk/vl3;

    move-result-object p1

    sget-object v0, Llyiahf/vczjk/vl3;->OooOOOO:Llyiahf/vczjk/vl3;

    if-ne p1, v0, :cond_3

    iget-object p1, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v0, p0, Llyiahf/vczjk/eq1;->$manager:Llyiahf/vczjk/mk9;

    invoke-static {v0, v2}, Llyiahf/vczjk/ok6;->OooOoO(Llyiahf/vczjk/mk9;Z)Z

    move-result v0

    iget-object p1, p1, Llyiahf/vczjk/lx4;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v0

    check-cast p1, Llyiahf/vczjk/fw8;

    invoke-virtual {p1, v0}, Llyiahf/vczjk/fw8;->setValue(Ljava/lang/Object;)V

    :cond_3
    :goto_2
    iget-object p1, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v0, p0, Llyiahf/vczjk/eq1;->$value:Llyiahf/vczjk/gl9;

    iget-object v2, p0, Llyiahf/vczjk/eq1;->$offsetMapping:Llyiahf/vczjk/s86;

    invoke-static {p1, v0, v2}, Llyiahf/vczjk/sb;->Oooo0OO(Llyiahf/vczjk/lx4;Llyiahf/vczjk/gl9;Llyiahf/vczjk/s86;)V

    iget-object p1, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {p1}, Llyiahf/vczjk/lx4;->OooO0Oo()Llyiahf/vczjk/nm9;

    move-result-object p1

    if-eqz p1, :cond_5

    iget-object v0, p0, Llyiahf/vczjk/eq1;->$state:Llyiahf/vczjk/lx4;

    iget-object v3, p0, Llyiahf/vczjk/eq1;->$value:Llyiahf/vczjk/gl9;

    iget-object v4, p0, Llyiahf/vczjk/eq1;->$offsetMapping:Llyiahf/vczjk/s86;

    iget-object v2, v0, Llyiahf/vczjk/lx4;->OooO0o0:Llyiahf/vczjk/yl9;

    if-eqz v2, :cond_5

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_5

    iget-object v0, p1, Llyiahf/vczjk/nm9;->OooO0O0:Llyiahf/vczjk/xn4;

    if-eqz v0, :cond_5

    invoke-interface {v0}, Llyiahf/vczjk/xn4;->OooOO0o()Z

    move-result v5

    if-nez v5, :cond_4

    goto :goto_3

    :cond_4
    iget-object v5, p1, Llyiahf/vczjk/nm9;->OooO0OO:Llyiahf/vczjk/xn4;

    if-eqz v5, :cond_5

    new-instance v6, Llyiahf/vczjk/ni9;

    invoke-direct {v6, v0}, Llyiahf/vczjk/ni9;-><init>(Llyiahf/vczjk/xn4;)V

    invoke-static {v0}, Llyiahf/vczjk/ok6;->Oooo0(Llyiahf/vczjk/xn4;)Llyiahf/vczjk/wj7;

    move-result-object v7

    invoke-interface {v0, v5, v1}, Llyiahf/vczjk/xn4;->OooOOO0(Llyiahf/vczjk/xn4;Z)Llyiahf/vczjk/wj7;

    move-result-object v8

    iget-object v0, v2, Llyiahf/vczjk/yl9;->OooO00o:Llyiahf/vczjk/tl9;

    iget-object v0, v0, Llyiahf/vczjk/tl9;->OooO0O0:Ljava/util/concurrent/atomic/AtomicReference;

    invoke-virtual {v0}, Ljava/util/concurrent/atomic/AtomicReference;->get()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/yl9;

    invoke-static {v0, v2}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-eqz v0, :cond_5

    iget-object v2, v2, Llyiahf/vczjk/yl9;->OooO0O0:Llyiahf/vczjk/tx6;

    iget-object v5, p1, Llyiahf/vczjk/nm9;->OooO00o:Llyiahf/vczjk/mm9;

    invoke-interface/range {v2 .. v8}, Llyiahf/vczjk/tx6;->OooO0OO(Llyiahf/vczjk/gl9;Llyiahf/vczjk/s86;Llyiahf/vczjk/mm9;Llyiahf/vczjk/ni9;Llyiahf/vczjk/wj7;Llyiahf/vczjk/wj7;)V

    :cond_5
    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1
.end method
