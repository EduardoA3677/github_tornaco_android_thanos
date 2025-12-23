.class public final synthetic Llyiahf/vczjk/h60;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/yu;

.field public final synthetic OooOOO0:I

.field public final synthetic OooOOOO:Llyiahf/vczjk/oe3;

.field public final synthetic OooOOOo:Z


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/yu;Llyiahf/vczjk/oe3;ZII)V
    .locals 0

    iput p5, p0, Llyiahf/vczjk/h60;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/h60;->OooOOO:Llyiahf/vczjk/yu;

    iput-object p2, p0, Llyiahf/vczjk/h60;->OooOOOO:Llyiahf/vczjk/oe3;

    iput-boolean p3, p0, Llyiahf/vczjk/h60;->OooOOOo:Z

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/h60;->OooOOO0:I

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Integer;

    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    packed-switch v0, :pswitch_data_0

    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/h60;->OooOOOO:Llyiahf/vczjk/oe3;

    iget-boolean v1, p0, Llyiahf/vczjk/h60;->OooOOOo:Z

    iget-object v2, p0, Llyiahf/vczjk/h60;->OooOOO:Llyiahf/vczjk/yu;

    invoke-static {v2, v0, v1, p1, p2}, Llyiahf/vczjk/qqa;->OooO0o(Llyiahf/vczjk/yu;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    const/4 p2, 0x1

    invoke-static {p2}, Llyiahf/vczjk/ok6;->Oooo00o(I)I

    move-result p2

    iget-object v0, p0, Llyiahf/vczjk/h60;->OooOOOO:Llyiahf/vczjk/oe3;

    iget-boolean v1, p0, Llyiahf/vczjk/h60;->OooOOOo:Z

    iget-object v2, p0, Llyiahf/vczjk/h60;->OooOOO:Llyiahf/vczjk/yu;

    invoke-static {v2, v0, v1, p1, p2}, Llyiahf/vczjk/qqa;->OooO00o(Llyiahf/vczjk/yu;Llyiahf/vczjk/oe3;ZLlyiahf/vczjk/rf1;I)V

    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
