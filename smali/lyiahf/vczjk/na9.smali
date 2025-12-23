.class public final synthetic Llyiahf/vczjk/na9;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field public final synthetic OooOOO0:I


# direct methods
.method public synthetic constructor <init>(I)V
    .locals 0

    iput p1, p0, Llyiahf/vczjk/na9;->OooOOO0:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 3

    const/4 v0, 0x0

    const/4 v1, 0x1

    iget v2, p0, Llyiahf/vczjk/na9;->OooOOO0:I

    packed-switch v2, :pswitch_data_0

    sget-object v0, Llyiahf/vczjk/vo;->OooO00o:Lgithub/tornaco/android/thanos/core/Logger;

    invoke-static {v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;)Ljava/lang/Object;

    new-instance v0, Llyiahf/vczjk/d96;

    invoke-direct {v0}, Llyiahf/vczjk/d96;-><init>()V

    new-instance v2, Llyiahf/vczjk/e96;

    invoke-direct {v2, v0}, Llyiahf/vczjk/e96;-><init>(Llyiahf/vczjk/d96;)V

    new-instance v0, Llyiahf/vczjk/pb7;

    invoke-direct {v0, v1}, Llyiahf/vczjk/pb7;-><init>(I)V

    const-string v1, "http://thanox.emui.tech/api/"

    invoke-virtual {v0, v1}, Llyiahf/vczjk/pb7;->OooO(Ljava/lang/String;)V

    invoke-static {}, Llyiahf/vczjk/pk3;->OooO0OO()Llyiahf/vczjk/pk3;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/pb7;->OooO0O0(Llyiahf/vczjk/pk3;)V

    iput-object v2, v0, Llyiahf/vczjk/pb7;->OooOOO:Ljava/lang/Object;

    invoke-virtual {v0}, Llyiahf/vczjk/pb7;->OooOO0()Llyiahf/vczjk/mi;

    move-result-object v0

    const-class v1, Llyiahf/vczjk/cp;

    invoke-virtual {v0, v1}, Llyiahf/vczjk/mi;->OooO0oO(Ljava/lang/Class;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/cp;

    return-object v0

    :pswitch_0
    new-instance v1, Llyiahf/vczjk/n6a;

    const/16 v2, 0x7fff

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/n6a;-><init>(Llyiahf/vczjk/rn9;I)V

    return-object v1

    :pswitch_1
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0

    :pswitch_2
    sget v0, Llyiahf/vczjk/gx9;->OooO00o:F

    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object v0

    :pswitch_3
    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "CompositionLocal LocalShortXColorSchema not present"

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0

    :pswitch_4
    new-instance v1, Llyiahf/vczjk/eq9;

    invoke-direct {v1, v0}, Llyiahf/vczjk/eq9;-><init>(Llyiahf/vczjk/pq9;)V

    return-object v1

    :pswitch_5
    new-instance v0, Llyiahf/vczjk/d57;

    invoke-direct {v0, v1}, Llyiahf/vczjk/d57;-><init>(Z)V

    return-object v0

    :pswitch_6
    sget-object v0, Llyiahf/vczjk/u6a;->OooO00o:Llyiahf/vczjk/rn9;

    return-object v0

    :pswitch_7
    const/4 v0, 0x0

    int-to-float v0, v0

    new-instance v1, Llyiahf/vczjk/wd2;

    invoke-direct {v1, v0}, Llyiahf/vczjk/wd2;-><init>(F)V

    return-object v1

    nop

    :pswitch_data_0
    .packed-switch 0x0
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
