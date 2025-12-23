.class public final synthetic Llyiahf/vczjk/l32;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/function/Consumer;


# instance fields
.field public final synthetic OooO00o:I

.field public final synthetic OooO0O0:Llyiahf/vczjk/wx7;

.field public final synthetic OooO0OO:Llyiahf/vczjk/gv2;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/l32;->OooO00o:I

    iput-object p1, p0, Llyiahf/vczjk/l32;->OooO0O0:Llyiahf/vczjk/wx7;

    iput-object p2, p0, Llyiahf/vczjk/l32;->OooO0OO:Llyiahf/vczjk/gv2;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;)V
    .locals 1

    iget v0, p0, Llyiahf/vczjk/l32;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    if-nez p1, :cond_0

    iget-object p1, p0, Llyiahf/vczjk/l32;->OooO0O0:Llyiahf/vczjk/wx7;

    iget-object v0, p0, Llyiahf/vczjk/l32;->OooO0OO:Llyiahf/vczjk/gv2;

    invoke-static {p1, v0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->OooO0O0(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V

    return-void

    :cond_0
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    :pswitch_0
    if-nez p1, :cond_1

    iget-object p1, p0, Llyiahf/vczjk/l32;->OooO0O0:Llyiahf/vczjk/wx7;

    iget-object v0, p0, Llyiahf/vczjk/l32;->OooO0OO:Llyiahf/vczjk/gv2;

    invoke-static {p1, v0}, Lorg/jeasy/rules/core/DefaultRulesEngine;->OooO00o(Llyiahf/vczjk/wx7;Llyiahf/vczjk/gv2;)V

    return-void

    :cond_1
    new-instance p1, Ljava/lang/ClassCastException;

    invoke-direct {p1}, Ljava/lang/ClassCastException;-><init>()V

    throw p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
