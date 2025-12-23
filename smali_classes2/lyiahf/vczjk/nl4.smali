.class public final synthetic Llyiahf/vczjk/nl4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:I

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(III)V
    .locals 0

    iput p3, p0, Llyiahf/vczjk/nl4;->OooOOO0:I

    iput p1, p0, Llyiahf/vczjk/nl4;->OooOOO:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/nl4;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    packed-switch v0, :pswitch_data_0

    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget v0, p0, Llyiahf/vczjk/nl4;->OooOOO:I

    invoke-static {v0, p2, p1}, Llyiahf/vczjk/vt6;->OooO0o(IILlyiahf/vczjk/rf1;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget v0, p0, Llyiahf/vczjk/nl4;->OooOOO:I

    invoke-static {v0, p2, p1}, Llyiahf/vczjk/m6a;->OooO0Oo(IILlyiahf/vczjk/rf1;)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
