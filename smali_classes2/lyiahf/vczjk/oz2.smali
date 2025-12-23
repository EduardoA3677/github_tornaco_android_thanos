.class public final Llyiahf/vczjk/oz2;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/wf8;


# instance fields
.field public final synthetic OooO00o:I

.field public final OooO0O0:Ljava/lang/Object;

.field public final OooO0OO:Ljava/lang/Object;

.field public final OooO0Oo:Llyiahf/vczjk/cf3;


# direct methods
.method public constructor <init>(Ljava/io/File;Llyiahf/vczjk/b03;Llyiahf/vczjk/uu;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Llyiahf/vczjk/oz2;->OooO00o:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oz2;->OooO0O0:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/oz2;->OooO0OO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/oz2;->OooO0Oo:Llyiahf/vczjk/cf3;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/wf8;Llyiahf/vczjk/oe3;Llyiahf/vczjk/oe3;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Llyiahf/vczjk/oz2;->OooO00o:I

    const-string v0, "sequence"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "transformer"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/oz2;->OooO0O0:Ljava/lang/Object;

    iput-object p2, p0, Llyiahf/vczjk/oz2;->OooO0OO:Ljava/lang/Object;

    iput-object p3, p0, Llyiahf/vczjk/oz2;->OooO0Oo:Llyiahf/vczjk/cf3;

    return-void
.end method


# virtual methods
.method public final iterator()Ljava/util/Iterator;
    .locals 1

    iget v0, p0, Llyiahf/vczjk/oz2;->OooO00o:I

    packed-switch v0, :pswitch_data_0

    new-instance v0, Llyiahf/vczjk/d13;

    invoke-direct {v0, p0}, Llyiahf/vczjk/d13;-><init>(Llyiahf/vczjk/oz2;)V

    return-object v0

    :pswitch_0
    new-instance v0, Llyiahf/vczjk/mz2;

    invoke-direct {v0, p0}, Llyiahf/vczjk/mz2;-><init>(Llyiahf/vczjk/oz2;)V

    return-object v0

    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
