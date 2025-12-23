.class public final Llyiahf/vczjk/w8;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/of2;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/w8;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/w8;->OooO0O0:Ljava/lang/Object;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o(F)V
    .locals 5

    iget v0, p0, Llyiahf/vczjk/w8;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/w8;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/cs8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/cs8;->OooO0O0(F)V

    return-void

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/w8;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/y12;

    iget-object v0, v0, Llyiahf/vczjk/y12;->OooO00o:Llyiahf/vczjk/tf2;

    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    move-result-object p1

    invoke-virtual {v0, p1}, Llyiahf/vczjk/tf2;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    return-void

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/w8;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/d9;

    iget-object v1, v0, Llyiahf/vczjk/d9;->OooOOO:Llyiahf/vczjk/s8;

    invoke-virtual {v0}, Llyiahf/vczjk/d9;->OooO0o0()F

    move-result v2

    invoke-static {v2}, Ljava/lang/Float;->isNaN(F)Z

    move-result v2

    const/4 v3, 0x0

    if-eqz v2, :cond_0

    move v2, v3

    goto :goto_0

    :cond_0
    invoke-virtual {v0}, Llyiahf/vczjk/d9;->OooO0o0()F

    move-result v2

    :goto_0
    add-float/2addr v2, p1

    invoke-virtual {v0}, Llyiahf/vczjk/d9;->OooO0Oo()Llyiahf/vczjk/lb5;

    move-result-object p1

    iget-object p1, p1, Llyiahf/vczjk/lb5;->OooO00o:Ljava/lang/Object;

    invoke-interface {p1}, Ljava/util/Map;->values()Ljava/util/Collection;

    move-result-object p1

    check-cast p1, Ljava/lang/Iterable;

    invoke-static {p1}, Llyiahf/vczjk/d21;->o000000(Ljava/lang/Iterable;)Ljava/lang/Float;

    move-result-object p1

    const/high16 v4, 0x7fc00000    # Float.NaN

    if-eqz p1, :cond_1

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result p1

    goto :goto_1

    :cond_1
    move p1, v4

    :goto_1
    invoke-virtual {v0}, Llyiahf/vczjk/d9;->OooO0Oo()Llyiahf/vczjk/lb5;

    move-result-object v0

    iget-object v0, v0, Llyiahf/vczjk/lb5;->OooO00o:Ljava/lang/Object;

    invoke-interface {v0}, Ljava/util/Map;->values()Ljava/util/Collection;

    move-result-object v0

    check-cast v0, Ljava/lang/Iterable;

    invoke-static {v0}, Llyiahf/vczjk/d21;->o0O0O00(Ljava/lang/Iterable;)Ljava/lang/Float;

    move-result-object v0

    if-eqz v0, :cond_2

    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    move-result v4

    :cond_2
    invoke-static {v2, p1, v4}, Llyiahf/vczjk/vt6;->OooOOo0(FFF)F

    move-result p1

    iget-object v0, v1, Llyiahf/vczjk/s8;->OooO00o:Llyiahf/vczjk/d9;

    iget-object v1, v0, Llyiahf/vczjk/d9;->OooOO0:Llyiahf/vczjk/lr5;

    check-cast v1, Llyiahf/vczjk/zv8;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    iget-object p1, v0, Llyiahf/vczjk/d9;->OooOO0O:Llyiahf/vczjk/lr5;

    check-cast p1, Llyiahf/vczjk/zv8;

    invoke-virtual {p1, v3}, Llyiahf/vczjk/zv8;->OooOo00(F)V

    return-void

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/w8;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/c9;

    iget-object v1, v0, Llyiahf/vczjk/c9;->OooOOO:Llyiahf/vczjk/r8;

    invoke-virtual {v0, p1}, Llyiahf/vczjk/c9;->OooO0o(F)F

    move-result p1

    invoke-static {v1, p1}, Llyiahf/vczjk/r8;->OooO0O0(Llyiahf/vczjk/r8;F)V

    return-void

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
