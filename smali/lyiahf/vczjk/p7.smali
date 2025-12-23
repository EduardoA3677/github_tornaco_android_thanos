.class public final synthetic Llyiahf/vczjk/p7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/r8;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/el7;


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/r8;Llyiahf/vczjk/el7;I)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/p7;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/p7;->OooOOO:Llyiahf/vczjk/r8;

    iput-object p2, p0, Llyiahf/vczjk/p7;->OooOOOO:Llyiahf/vczjk/el7;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/p7;->OooOOO0:I

    check-cast p1, Ljava/lang/Float;

    invoke-virtual {p1}, Ljava/lang/Float;->floatValue()F

    move-result p1

    check-cast p2, Ljava/lang/Float;

    invoke-virtual {p2}, Ljava/lang/Float;->floatValue()F

    move-result p2

    packed-switch v0, :pswitch_data_0

    iget-object v0, p0, Llyiahf/vczjk/p7;->OooOOO:Llyiahf/vczjk/r8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/r8;->OooO00o(FF)V

    iget-object p2, p0, Llyiahf/vczjk/p7;->OooOOOO:Llyiahf/vczjk/el7;

    iput p1, p2, Llyiahf/vczjk/el7;->element:F

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/p7;->OooOOO:Llyiahf/vczjk/r8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/r8;->OooO00o(FF)V

    iget-object p2, p0, Llyiahf/vczjk/p7;->OooOOOO:Llyiahf/vczjk/el7;

    iput p1, p2, Llyiahf/vczjk/el7;->element:F

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/p7;->OooOOO:Llyiahf/vczjk/r8;

    invoke-virtual {v0, p1, p2}, Llyiahf/vczjk/r8;->OooO00o(FF)V

    iget-object p2, p0, Llyiahf/vczjk/p7;->OooOOOO:Llyiahf/vczjk/el7;

    iput p1, p2, Llyiahf/vczjk/el7;->element:F

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
