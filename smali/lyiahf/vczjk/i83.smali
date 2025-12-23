.class public final Llyiahf/vczjk/i83;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/h43;


# instance fields
.field public final synthetic OooOOO:Ljava/util/ArrayList;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/qs5;


# direct methods
.method public synthetic constructor <init>(Ljava/util/ArrayList;Llyiahf/vczjk/qs5;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/i83;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/i83;->OooOOO:Ljava/util/ArrayList;

    iput-object p2, p0, Llyiahf/vczjk/i83;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Llyiahf/vczjk/yo1;)Ljava/lang/Object;
    .locals 1

    iget p2, p0, Llyiahf/vczjk/i83;->OooOOO0:I

    packed-switch p2, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/j24;

    instance-of p2, p1, Llyiahf/vczjk/q37;

    iget-object v0, p0, Llyiahf/vczjk/i83;->OooOOO:Ljava/util/ArrayList;

    if-eqz p2, :cond_0

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_0
    instance-of p2, p1, Llyiahf/vczjk/r37;

    if-eqz p2, :cond_1

    check-cast p1, Llyiahf/vczjk/r37;

    iget-object p1, p1, Llyiahf/vczjk/r37;->OooO00o:Llyiahf/vczjk/q37;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    goto :goto_0

    :cond_1
    instance-of p2, p1, Llyiahf/vczjk/p37;

    if-eqz p2, :cond_2

    check-cast p1, Llyiahf/vczjk/p37;

    iget-object p1, p1, Llyiahf/vczjk/p37;->OooO00o:Llyiahf/vczjk/q37;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    :cond_2
    :goto_0
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p1

    xor-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/i83;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {p2, p1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/j24;

    instance-of p2, p1, Llyiahf/vczjk/g83;

    iget-object v0, p0, Llyiahf/vczjk/i83;->OooOOO:Ljava/util/ArrayList;

    if-eqz p2, :cond_3

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    goto :goto_1

    :cond_3
    instance-of p2, p1, Llyiahf/vczjk/h83;

    if-eqz p2, :cond_4

    check-cast p1, Llyiahf/vczjk/h83;

    iget-object p1, p1, Llyiahf/vczjk/h83;->OooO00o:Llyiahf/vczjk/g83;

    invoke-virtual {v0, p1}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    :cond_4
    :goto_1
    invoke-virtual {v0}, Ljava/util/ArrayList;->isEmpty()Z

    move-result p1

    xor-int/lit8 p1, p1, 0x1

    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    move-result-object p1

    iget-object p2, p0, Llyiahf/vczjk/i83;->OooOOOO:Llyiahf/vczjk/qs5;

    invoke-interface {p2, p1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
