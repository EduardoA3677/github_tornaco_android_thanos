.class public final Llyiahf/vczjk/ne1;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/ze3;


# instance fields
.field public final synthetic OooOOO:Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;

.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;I)V
    .locals 0

    iput p2, p0, Llyiahf/vczjk/ne1;->OooOOO0:I

    iput-object p1, p0, Llyiahf/vczjk/ne1;->OooOOO:Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    iget v0, p0, Llyiahf/vczjk/ne1;->OooOOO0:I

    packed-switch v0, :pswitch_data_0

    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_1

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_0

    goto :goto_0

    :cond_0
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_1

    :cond_1
    :goto_0
    sget-object p2, Llyiahf/vczjk/bh1;->OooO00o:Llyiahf/vczjk/l39;

    iget-object v0, p0, Llyiahf/vczjk/ne1;->OooOOO:Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;

    invoke-virtual {p2, v0}, Llyiahf/vczjk/l39;->OooO00o(Ljava/lang/Object;)Llyiahf/vczjk/ke7;

    move-result-object p2

    new-instance v1, Llyiahf/vczjk/ne1;

    const/4 v2, 0x0

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/ne1;-><init>(Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;I)V

    const v0, -0x53d37daf

    invoke-static {v0, v1, p1}, Llyiahf/vczjk/zsa;->o0OoOo0(ILlyiahf/vczjk/cf3;Llyiahf/vczjk/rf1;)Llyiahf/vczjk/a91;

    move-result-object v0

    const/16 v1, 0x38

    invoke-static {p2, v0, p1, v1}, Llyiahf/vczjk/r02;->OooO00o(Llyiahf/vczjk/ke7;Llyiahf/vczjk/ze3;Llyiahf/vczjk/rf1;I)V

    :goto_1
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    :pswitch_0
    check-cast p1, Llyiahf/vczjk/rf1;

    check-cast p2, Ljava/lang/Number;

    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    move-result p2

    and-int/lit8 p2, p2, 0x3

    const/4 v0, 0x2

    if-ne p2, v0, :cond_3

    move-object p2, p1

    check-cast p2, Llyiahf/vczjk/zf1;

    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->OooOo()Z

    move-result v0

    if-nez v0, :cond_2

    goto :goto_2

    :cond_2
    invoke-virtual {p2}, Llyiahf/vczjk/zf1;->Oooo0oO()V

    goto :goto_3

    :cond_3
    :goto_2
    iget-object p2, p0, Llyiahf/vczjk/ne1;->OooOOO:Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;

    const/4 v0, 0x0

    invoke-virtual {p2, v0, p1}, Lgithub/tornaco/android/thanos/module/compose/common/ComposeThemeActivity;->OooOoOO(ILlyiahf/vczjk/rf1;)V

    :goto_3
    sget-object p1, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    return-object p1

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
