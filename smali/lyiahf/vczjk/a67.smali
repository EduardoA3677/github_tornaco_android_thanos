.class public final synthetic Llyiahf/vczjk/a67;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/qs5;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/a77;Llyiahf/vczjk/qs5;)V
    .locals 0

    const/4 p1, 0x0

    iput p1, p0, Llyiahf/vczjk/a67;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p2, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    return-void
.end method

.method public synthetic constructor <init>(Llyiahf/vczjk/qs5;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/a67;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/a67;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-interface {v0, v1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-interface {v0, v1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    sget-object v1, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    invoke-interface {v0, v1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_2
    iget-object v0, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-interface {v0, v1}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_3
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_4
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_5
    iget-object v0, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/util/List;

    invoke-interface {v0}, Ljava/util/List;->size()I

    move-result v0

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    return-object v0

    :pswitch_6
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_7
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_8
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_9
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_a
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_b
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    iget-object v1, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v1, v0}, Llyiahf/vczjk/qs5;->setValue(Ljava/lang/Object;)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_c
    iget-object v0, p0, Llyiahf/vczjk/a67;->OooOOO:Llyiahf/vczjk/qs5;

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cm4;

    iget-boolean v0, v0, Llyiahf/vczjk/cm4;->OooO00o:Z

    if-eqz v0, :cond_0

    goto :goto_0

    :cond_0
    sget-object v0, Llyiahf/vczjk/im4;->OooO00o:Llyiahf/vczjk/im4;

    invoke-virtual {v0}, Llyiahf/vczjk/im4;->OooO00o()V

    :goto_0
    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
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
