.class public final Llyiahf/vczjk/p26;
.super Ljava/lang/Object;

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/ld9;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/ld9;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/p26;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/p26;->OooOOO:Llyiahf/vczjk/ld9;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    iget v0, p0, Llyiahf/vczjk/p26;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/q26;

    const-string v0, "<destruct>"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    iget-object v0, p1, Llyiahf/vczjk/q26;->OooO00o:Llyiahf/vczjk/hy0;

    iget-boolean v1, v0, Llyiahf/vczjk/hy0;->OooO0OO:Z

    if-nez v1, :cond_2

    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->OooO0o0()Llyiahf/vczjk/hy0;

    move-result-object v1

    iget-object p1, p1, Llyiahf/vczjk/q26;->OooO0O0:Ljava/util/List;

    iget-object v2, p0, Llyiahf/vczjk/p26;->OooOOO:Llyiahf/vczjk/ld9;

    if-eqz v1, :cond_0

    const/4 v3, 0x1

    invoke-static {v3, p1}, Llyiahf/vczjk/d21;->o0OoOo0(ILjava/util/List;)Ljava/util/List;

    move-result-object v3

    invoke-virtual {v2, v1, v3}, Llyiahf/vczjk/ld9;->OoooO(Llyiahf/vczjk/hy0;Ljava/util/List;)Llyiahf/vczjk/by0;

    move-result-object v1

    :goto_0
    move-object v5, v1

    goto :goto_1

    :cond_0
    iget-object v1, v2, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/l45;

    iget-object v3, v0, Llyiahf/vczjk/hy0;->OooO00o:Llyiahf/vczjk/hc3;

    invoke-virtual {v1, v3}, Llyiahf/vczjk/l45;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v1

    check-cast v1, Llyiahf/vczjk/py0;

    goto :goto_0

    :goto_1
    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->OooO0oO()Z

    move-result v7

    new-instance v3, Llyiahf/vczjk/r26;

    iget-object v1, v2, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/q45;

    invoke-virtual {v0}, Llyiahf/vczjk/hy0;->OooO0o()Llyiahf/vczjk/qt5;

    move-result-object v6

    invoke-static {p1}, Llyiahf/vczjk/d21;->oo000o(Ljava/util/List;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Integer;

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    move-result p1

    :goto_2
    move v8, p1

    goto :goto_3

    :cond_1
    const/4 p1, 0x0

    goto :goto_2

    :goto_3
    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/r26;-><init>(Llyiahf/vczjk/q45;Llyiahf/vczjk/py0;Llyiahf/vczjk/qt5;ZI)V

    return-object v3

    :cond_2
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    new-instance v1, Ljava/lang/StringBuilder;

    const-string v2, "Unresolved local class: "

    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    invoke-direct {p1, v0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/hc3;

    const-string v0, "fqName"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    new-instance v0, Llyiahf/vczjk/dn2;

    iget-object v1, p0, Llyiahf/vczjk/p26;->OooOOO:Llyiahf/vczjk/ld9;

    iget-object v1, v1, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/cm5;

    const/4 v2, 0x0

    invoke-direct {v0, v1, p1, v2}, Llyiahf/vczjk/dn2;-><init>(Llyiahf/vczjk/cm5;Llyiahf/vczjk/hc3;I)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
