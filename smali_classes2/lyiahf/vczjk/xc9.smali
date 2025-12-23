.class public final Llyiahf/vczjk/xc9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/cd5;


# static fields
.field public static final OooO0O0:Llyiahf/vczjk/xc9;


# instance fields
.field public final synthetic OooO00o:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/xc9;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/xc9;-><init>(I)V

    sput-object v0, Llyiahf/vczjk/xc9;->OooO0O0:Llyiahf/vczjk/xc9;

    return-void
.end method

.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/xc9;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/ld9;Llyiahf/vczjk/ak1;)V
    .locals 6

    iget v0, p0, Llyiahf/vczjk/xc9;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    check-cast p2, Llyiahf/vczjk/mg9;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    sget-object v1, Llyiahf/vczjk/dn8;->OooOo0o:Llyiahf/vczjk/ja7;

    iget-boolean v2, p2, Llyiahf/vczjk/mg9;->OooO0oO:Z

    invoke-static {v2}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v2

    iget-object v3, p1, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/pi4;

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    iget-object v1, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/wc5;

    iget-object v2, v1, Llyiahf/vczjk/wc5;->OooO0oO:Llyiahf/vczjk/sw7;

    const-class v4, Llyiahf/vczjk/mg9;

    invoke-virtual {v2, v4}, Llyiahf/vczjk/sw7;->OooOO0(Ljava/lang/Class;)Llyiahf/vczjk/cy8;

    move-result-object v2

    if-eqz v2, :cond_1

    invoke-interface {v2, v1, v3}, Llyiahf/vczjk/cy8;->OooO00o(Llyiahf/vczjk/wc5;Llyiahf/vczjk/pi4;)Ljava/lang/Object;

    move-result-object v1

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/ld9;->Oooooo0(ILjava/lang/Object;)V

    iget-object p2, p2, Llyiahf/vczjk/ak1;->OooO0o:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/ak1;

    if-eqz p2, :cond_0

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->Oooo0o()V

    :cond_0
    return-void

    :cond_1
    new-instance p1, Ljava/lang/NullPointerException;

    invoke-virtual {v4}, Ljava/lang/Class;->getName()Ljava/lang/String;

    move-result-object p2

    invoke-direct {p1, p2}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1

    :pswitch_0
    check-cast p2, Llyiahf/vczjk/he9;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->Oooo0o()V

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    new-instance v1, Llyiahf/vczjk/we9;

    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    invoke-virtual {p1, v0, v1}, Llyiahf/vczjk/ld9;->Oooooo0(ILjava/lang/Object;)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->OooOooo(Llyiahf/vczjk/ak1;)V

    return-void

    :pswitch_1
    check-cast p2, Llyiahf/vczjk/f69;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    return-void

    :pswitch_2
    check-cast p2, Llyiahf/vczjk/cx8;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->Oooo0o()V

    return-void

    :pswitch_3
    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->Oooo0o()V

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->OooOooo(Llyiahf/vczjk/ak1;)V

    return-void

    :pswitch_4
    check-cast p2, Llyiahf/vczjk/c15;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    iget-object v1, p2, Llyiahf/vczjk/ak1;->OooO0O0:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/ak1;

    check-cast v1, Llyiahf/vczjk/gd0;

    instance-of v2, v1, Llyiahf/vczjk/if6;

    sget-object v3, Llyiahf/vczjk/t51;->OooO00o:Llyiahf/vczjk/ja7;

    iget-object v4, p1, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/pi4;

    if-eqz v2, :cond_2

    check-cast v1, Llyiahf/vczjk/if6;

    iget v2, v1, Llyiahf/vczjk/if6;->OooO0oo:I

    sget-object v5, Llyiahf/vczjk/mp1;->OooOOO:Llyiahf/vczjk/mp1;

    invoke-virtual {v3, v4, v5}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    sget-object v3, Llyiahf/vczjk/t51;->OooO0OO:Llyiahf/vczjk/ja7;

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v3, v4, v2}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    iget v2, v1, Llyiahf/vczjk/if6;->OooO0oo:I

    add-int/lit8 v2, v2, 0x1

    iput v2, v1, Llyiahf/vczjk/if6;->OooO0oo:I

    goto :goto_1

    :cond_2
    sget-object v1, Llyiahf/vczjk/mp1;->OooOOO0:Llyiahf/vczjk/mp1;

    invoke-virtual {v3, v4, v1}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    sget-object v1, Llyiahf/vczjk/t51;->OooO0O0:Llyiahf/vczjk/ja7;

    iget-object v2, p2, Llyiahf/vczjk/ak1;->OooO0O0:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/ak1;

    check-cast v2, Llyiahf/vczjk/gd0;

    const/4 v3, 0x0

    :goto_0
    if-eqz v2, :cond_4

    instance-of v5, v2, Llyiahf/vczjk/c15;

    if-eqz v5, :cond_3

    add-int/lit8 v3, v3, 0x1

    :cond_3
    invoke-virtual {v2}, Llyiahf/vczjk/ak1;->OooO0Oo()Llyiahf/vczjk/ak1;

    move-result-object v2

    goto :goto_0

    :cond_4
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    invoke-virtual {v1, v4, v2}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    :goto_1
    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    iget-object p2, p2, Llyiahf/vczjk/ak1;->OooO0o:Ljava/lang/Object;

    check-cast p2, Llyiahf/vczjk/ak1;

    if-eqz p2, :cond_5

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->Oooo0o()V

    :cond_5
    return-void

    :pswitch_5
    check-cast p2, Llyiahf/vczjk/ju3;

    iget-object v0, p1, Llyiahf/vczjk/ld9;->OooOOO:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/wc5;

    const-class v1, Llyiahf/vczjk/ju3;

    iget-object v2, v0, Llyiahf/vczjk/wc5;->OooO0oO:Llyiahf/vczjk/sw7;

    invoke-virtual {v2, v1}, Llyiahf/vczjk/sw7;->OooOO0(Ljava/lang/Class;)Llyiahf/vczjk/cy8;

    move-result-object v1

    if-nez v1, :cond_6

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    goto :goto_2

    :cond_6
    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v2

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v3

    if-ne v2, v3, :cond_7

    iget-object v3, p1, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/iy8;

    const v4, 0xfffc

    invoke-virtual {v3, v4}, Llyiahf/vczjk/iy8;->OooO00o(C)V

    :cond_7
    iget-object v3, p2, Llyiahf/vczjk/ak1;->OooO0O0:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/ak1;

    instance-of v3, v3, Llyiahf/vczjk/b05;

    iget-object v4, v0, Llyiahf/vczjk/wc5;->OooO0o0:Llyiahf/vczjk/pp3;

    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget-object v4, Llyiahf/vczjk/e16;->OooO0OO:Llyiahf/vczjk/ja7;

    iget-object p2, p2, Llyiahf/vczjk/ju3;->OooO0oO:Ljava/lang/String;

    iget-object v5, p1, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v5, Llyiahf/vczjk/pi4;

    invoke-virtual {v4, v5, p2}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    sget-object p2, Llyiahf/vczjk/e16;->OooO0Oo:Llyiahf/vczjk/ja7;

    invoke-static {v3}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v3

    invoke-virtual {p2, v5, v3}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    sget-object p2, Llyiahf/vczjk/e16;->OooO0o0:Llyiahf/vczjk/ja7;

    const/4 v3, 0x0

    invoke-virtual {p2, v5, v3}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    invoke-interface {v1, v0, v5}, Llyiahf/vczjk/cy8;->OooO00o(Llyiahf/vczjk/wc5;Llyiahf/vczjk/pi4;)Ljava/lang/Object;

    move-result-object p2

    invoke-virtual {p1, v2, p2}, Llyiahf/vczjk/ld9;->Oooooo0(ILjava/lang/Object;)V

    :goto_2
    return-void

    :pswitch_6
    check-cast p2, Llyiahf/vczjk/sw3;

    iget-object v0, p2, Llyiahf/vczjk/sw3;->OooO0oO:Ljava/lang/String;

    const/4 v1, 0x0

    invoke-static {p1, v1, v0, p2}, Llyiahf/vczjk/lp1;->OooOO0O(Llyiahf/vczjk/ld9;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/gd0;)V

    return-void

    :pswitch_7
    check-cast p2, Llyiahf/vczjk/zw2;

    iget-object v0, p2, Llyiahf/vczjk/zw2;->OooOO0:Ljava/lang/String;

    iget-object v1, p2, Llyiahf/vczjk/zw2;->OooOO0O:Ljava/lang/String;

    invoke-static {p1, v0, v1, p2}, Llyiahf/vczjk/lp1;->OooOO0O(Llyiahf/vczjk/ld9;Ljava/lang/String;Ljava/lang/String;Llyiahf/vczjk/gd0;)V

    return-void

    :pswitch_8
    check-cast p2, Llyiahf/vczjk/s01;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    iget-object v1, p1, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/iy8;

    iget-object v2, v1, Llyiahf/vczjk/iy8;->OooOOO0:Ljava/lang/StringBuilder;

    const/16 v3, 0xa0

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    iget-object v4, p2, Llyiahf/vczjk/s01;->OooO0oO:Ljava/lang/String;

    invoke-virtual {v2, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v1, v3}, Llyiahf/vczjk/iy8;->OooO00o(C)V

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    return-void

    :pswitch_9
    check-cast p2, Llyiahf/vczjk/md0;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->Oooo0o()V

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->OooOooo(Llyiahf/vczjk/ak1;)V

    return-void

    :pswitch_a
    check-cast p2, Llyiahf/vczjk/lm2;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    return-void

    :pswitch_b
    check-cast p2, Llyiahf/vczjk/j79;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    return-void

    :pswitch_c
    check-cast p2, Llyiahf/vczjk/b05;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    sget-object v1, Llyiahf/vczjk/t51;->OooO0o0:Llyiahf/vczjk/ja7;

    iget-object v2, p1, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v2, Llyiahf/vczjk/pi4;

    iget-object v3, p2, Llyiahf/vczjk/b05;->OooO0oO:Ljava/lang/String;

    invoke-virtual {v1, v2, v3}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    return-void

    :pswitch_d
    check-cast p2, Llyiahf/vczjk/ao6;

    iget-object v0, p2, Llyiahf/vczjk/ak1;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ak1;

    check-cast v0, Llyiahf/vczjk/gd0;

    if-eqz v0, :cond_8

    iget-object v0, v0, Llyiahf/vczjk/ak1;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ak1;

    check-cast v0, Llyiahf/vczjk/gd0;

    instance-of v1, v0, Llyiahf/vczjk/u05;

    if-eqz v1, :cond_8

    check-cast v0, Llyiahf/vczjk/u05;

    iget-boolean v0, v0, Llyiahf/vczjk/u05;->OooO0oO:Z

    goto :goto_3

    :cond_8
    const/4 v0, 0x0

    :goto_3
    if-nez v0, :cond_9

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->Oooo0o()V

    :cond_9
    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v1

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    sget-object v2, Llyiahf/vczjk/t51;->OooO0o:Llyiahf/vczjk/ja7;

    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object v3

    iget-object v4, p1, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v4, Llyiahf/vczjk/pi4;

    invoke-virtual {v2, v4, v3}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    invoke-virtual {p1, p2, v1}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    if-nez v0, :cond_a

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->OooOooo(Llyiahf/vczjk/ak1;)V

    :cond_a
    return-void

    :pswitch_e
    check-cast p2, Llyiahf/vczjk/km3;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->Oooo0o()V

    return-void

    :pswitch_f
    check-cast p2, Llyiahf/vczjk/cx8;

    iget-object p1, p1, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast p1, Llyiahf/vczjk/iy8;

    const/16 p2, 0x20

    invoke-virtual {p1, p2}, Llyiahf/vczjk/iy8;->OooO00o(C)V

    return-void

    :pswitch_10
    check-cast p2, Llyiahf/vczjk/wm3;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->Oooo0o()V

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    sget-object v1, Llyiahf/vczjk/t51;->OooO0Oo:Llyiahf/vczjk/ja7;

    iget v2, p2, Llyiahf/vczjk/wm3;->OooO0oO:I

    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v2

    iget-object v3, p1, Llyiahf/vczjk/ld9;->OooOOOO:Ljava/lang/Object;

    check-cast v3, Llyiahf/vczjk/pi4;

    invoke-virtual {v1, v3, v2}, Llyiahf/vczjk/ja7;->OooO0O0(Llyiahf/vczjk/pi4;Ljava/lang/Object;)V

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->OooOooo(Llyiahf/vczjk/ak1;)V

    return-void

    :pswitch_11
    check-cast p2, Llyiahf/vczjk/cq9;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->Oooo0o()V

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    iget-object v1, p1, Llyiahf/vczjk/ld9;->OooOOOo:Ljava/lang/Object;

    check-cast v1, Llyiahf/vczjk/iy8;

    const/16 v2, 0xa0

    invoke-virtual {v1, v2}, Llyiahf/vczjk/iy8;->OooO00o(C)V

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->OooOooo(Llyiahf/vczjk/ak1;)V

    return-void

    :pswitch_12
    check-cast p2, Llyiahf/vczjk/vc9;

    invoke-virtual {p1}, Llyiahf/vczjk/ld9;->OoooOoo()I

    move-result v0

    invoke-virtual {p1, p2}, Llyiahf/vczjk/ld9;->Ooooooo(Llyiahf/vczjk/ak1;)V

    invoke-virtual {p1, p2, v0}, Llyiahf/vczjk/ld9;->Oooooo(Llyiahf/vczjk/ak1;I)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_12
        :pswitch_11
        :pswitch_10
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
