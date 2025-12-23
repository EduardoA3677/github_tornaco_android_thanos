.class public final synthetic Llyiahf/vczjk/la2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/w41;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/w41;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/la2;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/la2;->OooOOO:Llyiahf/vczjk/w41;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 2

    iget v0, p0, Llyiahf/vczjk/la2;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    const/4 v0, 0x1

    iget-object v1, p0, Llyiahf/vczjk/la2;->OooOOO:Llyiahf/vczjk/w41;

    invoke-virtual {v1, v0}, Llyiahf/vczjk/w41;->OooO0OO(Z)V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_0
    iget-object v0, p0, Llyiahf/vczjk/la2;->OooOOO:Llyiahf/vczjk/w41;

    invoke-virtual {v0}, Llyiahf/vczjk/w41;->OooO00o()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_1
    iget-object v0, p0, Llyiahf/vczjk/la2;->OooOOO:Llyiahf/vczjk/w41;

    invoke-virtual {v0}, Llyiahf/vczjk/w41;->OooO00o()V

    sget-object v0, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object v0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
