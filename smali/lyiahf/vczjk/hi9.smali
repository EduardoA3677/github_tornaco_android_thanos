.class public final Llyiahf/vczjk/hi9;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/bf3;


# instance fields
.field final synthetic $cursorBrush:Llyiahf/vczjk/ri0;

.field final synthetic $offsetMapping:Llyiahf/vczjk/s86;

.field final synthetic $state:Llyiahf/vczjk/lx4;

.field final synthetic $value:Llyiahf/vczjk/gl9;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ri0;Llyiahf/vczjk/lx4;Llyiahf/vczjk/gl9;Llyiahf/vczjk/s86;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/hi9;->$cursorBrush:Llyiahf/vczjk/ri0;

    iput-object p2, p0, Llyiahf/vczjk/hi9;->$state:Llyiahf/vczjk/lx4;

    iput-object p3, p0, Llyiahf/vczjk/hi9;->$value:Llyiahf/vczjk/gl9;

    iput-object p4, p0, Llyiahf/vczjk/hi9;->$offsetMapping:Llyiahf/vczjk/s86;

    const/4 p1, 0x3

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o0(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 9

    check-cast p1, Llyiahf/vczjk/kl5;

    check-cast p2, Llyiahf/vczjk/rf1;

    check-cast p3, Ljava/lang/Number;

    invoke-virtual {p3}, Ljava/lang/Number;->intValue()I

    check-cast p2, Llyiahf/vczjk/zf1;

    const p3, -0x5097aed    # -6.4000205E35f

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    sget-object p3, Llyiahf/vczjk/ch1;->OooOo0o:Llyiahf/vczjk/l39;

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object p3

    check-cast p3, Ljava/lang/Boolean;

    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    move-result p3

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OooO0oo(Z)Z

    move-result v0

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v1

    sget-object v2, Llyiahf/vczjk/qf1;->OooO00o:Llyiahf/vczjk/tp3;

    if-nez v0, :cond_0

    if-ne v1, v2, :cond_1

    :cond_0
    new-instance v1, Llyiahf/vczjk/ou1;

    invoke-direct {v1, p3}, Llyiahf/vczjk/ou1;-><init>(Z)V

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_1
    move-object v4, v1

    check-cast v4, Llyiahf/vczjk/ou1;

    iget-object p3, p0, Llyiahf/vczjk/hi9;->$cursorBrush:Llyiahf/vczjk/ri0;

    instance-of v0, p3, Llyiahf/vczjk/gx8;

    const/4 v1, 0x0

    if-eqz v0, :cond_2

    check-cast p3, Llyiahf/vczjk/gx8;

    iget-wide v5, p3, Llyiahf/vczjk/gx8;->OooO00o:J

    const-wide/16 v7, 0x10

    cmp-long p3, v5, v7

    if-nez p3, :cond_2

    move p3, v1

    goto :goto_0

    :cond_2
    const/4 p3, 0x1

    :goto_0
    sget-object v0, Llyiahf/vczjk/ch1;->OooOo00:Llyiahf/vczjk/l39;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooOO0O(Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/bna;

    check-cast v0, Llyiahf/vczjk/yw4;

    iget-object v0, v0, Llyiahf/vczjk/yw4;->OooO0OO:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Boolean;

    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v0

    if-eqz v0, :cond_7

    iget-object v0, p0, Llyiahf/vczjk/hi9;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {v0}, Llyiahf/vczjk/lx4;->OooO0O0()Z

    move-result v0

    if-eqz v0, :cond_7

    iget-object v0, p0, Llyiahf/vczjk/hi9;->$value:Llyiahf/vczjk/gl9;

    iget-wide v5, v0, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-static {v5, v6}, Llyiahf/vczjk/gn9;->OooO0O0(J)Z

    move-result v0

    if-eqz v0, :cond_7

    if-eqz p3, :cond_7

    const p3, 0x303022be

    invoke-virtual {p2, p3}, Llyiahf/vczjk/zf1;->OoooO(I)V

    iget-object p3, p0, Llyiahf/vczjk/hi9;->$value:Llyiahf/vczjk/gl9;

    iget-object v0, p3, Llyiahf/vczjk/gl9;->OooO00o:Llyiahf/vczjk/an;

    new-instance v3, Llyiahf/vczjk/gn9;

    iget-wide v5, p3, Llyiahf/vczjk/gl9;->OooO0O0:J

    invoke-direct {v3, v5, v6}, Llyiahf/vczjk/gn9;-><init>(J)V

    invoke-virtual {p2, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p3

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v5

    if-nez p3, :cond_3

    if-ne v5, v2, :cond_4

    :cond_3
    new-instance v5, Llyiahf/vczjk/fi9;

    const/4 p3, 0x0

    invoke-direct {v5, v4, p3}, Llyiahf/vczjk/fi9;-><init>(Llyiahf/vczjk/ou1;Llyiahf/vczjk/yo1;)V

    invoke-virtual {p2, v5}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    :cond_4
    check-cast v5, Llyiahf/vczjk/ze3;

    invoke-static {v0, v3, v5, p2}, Llyiahf/vczjk/c6a;->OooOOOo(Ljava/lang/Object;Ljava/lang/Object;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;)V

    invoke-virtual {p2, v4}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result p3

    iget-object v0, p0, Llyiahf/vczjk/hi9;->$offsetMapping:Llyiahf/vczjk/s86;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    or-int/2addr p3, v0

    iget-object v0, p0, Llyiahf/vczjk/hi9;->$value:Llyiahf/vczjk/gl9;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    or-int/2addr p3, v0

    iget-object v0, p0, Llyiahf/vczjk/hi9;->$state:Llyiahf/vczjk/lx4;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooO(Ljava/lang/Object;)Z

    move-result v0

    or-int/2addr p3, v0

    iget-object v0, p0, Llyiahf/vczjk/hi9;->$cursorBrush:Llyiahf/vczjk/ri0;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/zf1;->OooO0oO(Ljava/lang/Object;)Z

    move-result v0

    or-int/2addr p3, v0

    iget-object v5, p0, Llyiahf/vczjk/hi9;->$offsetMapping:Llyiahf/vczjk/s86;

    iget-object v6, p0, Llyiahf/vczjk/hi9;->$value:Llyiahf/vczjk/gl9;

    iget-object v7, p0, Llyiahf/vczjk/hi9;->$state:Llyiahf/vczjk/lx4;

    iget-object v8, p0, Llyiahf/vczjk/hi9;->$cursorBrush:Llyiahf/vczjk/ri0;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo00o()Ljava/lang/Object;

    move-result-object v0

    if-nez p3, :cond_5

    if-ne v0, v2, :cond_6

    :cond_5
    new-instance v3, Llyiahf/vczjk/gi9;

    invoke-direct/range {v3 .. v8}, Llyiahf/vczjk/gi9;-><init>(Llyiahf/vczjk/ou1;Llyiahf/vczjk/s86;Llyiahf/vczjk/gl9;Llyiahf/vczjk/lx4;Llyiahf/vczjk/ri0;)V

    invoke-virtual {p2, v3}, Llyiahf/vczjk/zf1;->OooooOO(Ljava/lang/Object;)V

    move-object v0, v3

    :cond_6
    check-cast v0, Llyiahf/vczjk/oe3;

    invoke-static {p1, v0}, Landroidx/compose/ui/draw/OooO00o;->OooO0OO(Llyiahf/vczjk/kl5;Llyiahf/vczjk/oe3;)Llyiahf/vczjk/kl5;

    move-result-object p1

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    goto :goto_1

    :cond_7
    const p1, 0x304edcfe

    invoke-virtual {p2, p1}, Llyiahf/vczjk/zf1;->OoooO(I)V

    invoke-virtual {p2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    sget-object p1, Llyiahf/vczjk/hl5;->OooOOO0:Llyiahf/vczjk/hl5;

    :goto_1
    invoke-virtual {p2, v1}, Llyiahf/vczjk/zf1;->OooOOOo(Z)V

    return-object p1
.end method
