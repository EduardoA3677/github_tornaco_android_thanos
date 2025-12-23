.class public abstract Llyiahf/vczjk/x95;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/ze8;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/ze8;

    const-string v1, "MagnifierPositionInRoot"

    invoke-direct {v0, v1}, Llyiahf/vczjk/ze8;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/x95;->OooO00o:Llyiahf/vczjk/ze8;

    return-void
.end method

.method public static OooO00o()Z
    .locals 2

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const/16 v1, 0x1c

    if-lt v0, v1, :cond_0

    const/4 v0, 0x1

    return v0

    :cond_0
    const/4 v0, 0x0

    return v0
.end method
