.class public final synthetic Llyiahf/vczjk/zf6;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO:Llyiahf/vczjk/vi9;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Llyiahf/vczjk/vi9;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/zf6;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/zf6;->OooOOO:Llyiahf/vczjk/vi9;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/zf6;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    sget v0, Llyiahf/vczjk/wi9;->OooO0Oo:F

    sget v1, Llyiahf/vczjk/wi9;->OooO0o0:F

    iget-object v2, p0, Llyiahf/vczjk/zf6;->OooOOO:Llyiahf/vczjk/vi9;

    invoke-virtual {v2}, Llyiahf/vczjk/vi9;->OooO00o()F

    move-result v2

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result v0

    new-instance v1, Llyiahf/vczjk/wd2;

    invoke-direct {v1, v0}, Llyiahf/vczjk/wd2;-><init>(F)V

    return-object v1

    :pswitch_0
    sget v0, Llyiahf/vczjk/wi9;->OooO0Oo:F

    sget v1, Llyiahf/vczjk/wi9;->OooO0o0:F

    iget-object v2, p0, Llyiahf/vczjk/zf6;->OooOOO:Llyiahf/vczjk/vi9;

    invoke-virtual {v2}, Llyiahf/vczjk/vi9;->OooO00o()F

    move-result v2

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/so8;->Oooo00O(FFF)F

    move-result v0

    new-instance v1, Llyiahf/vczjk/wd2;

    invoke-direct {v1, v0}, Llyiahf/vczjk/wd2;-><init>(F)V

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
