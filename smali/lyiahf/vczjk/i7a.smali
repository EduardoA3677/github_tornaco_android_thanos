.class public final Llyiahf/vczjk/i7a;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0o:I

.field public static OooO0o0:Llyiahf/vczjk/i7a;


# instance fields
.field public final OooO00o:Ljava/util/HashMap;

.field public final OooO0O0:Llyiahf/vczjk/a27;

.field public final OooO0OO:Llyiahf/vczjk/tf7;

.field public final OooO0Oo:Llyiahf/vczjk/m24;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    sget v0, Landroid/os/Build$VERSION;->SDK_INT:I

    const-string v1, "REL"

    sget-object v2, Landroid/os/Build$VERSION;->CODENAME:Ljava/lang/String;

    invoke-virtual {v1, v2}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    move-result v1

    xor-int/lit8 v1, v1, 0x1

    add-int/2addr v0, v1

    sput v0, Llyiahf/vczjk/i7a;->OooO0o:I

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/a27;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Ljava/util/HashMap;

    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/i7a;->OooO00o:Ljava/util/HashMap;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/i7a;->OooO0O0:Llyiahf/vczjk/a27;

    new-instance v0, Llyiahf/vczjk/tf7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/tf7;-><init>(Llyiahf/vczjk/a27;)V

    iput-object v0, p0, Llyiahf/vczjk/i7a;->OooO0OO:Llyiahf/vczjk/tf7;

    new-instance v0, Llyiahf/vczjk/m24;

    invoke-direct {v0, p1}, Llyiahf/vczjk/m24;-><init>(Llyiahf/vczjk/a27;)V

    iput-object v0, p0, Llyiahf/vczjk/i7a;->OooO0Oo:Llyiahf/vczjk/m24;

    sget v0, Llyiahf/vczjk/i7a;->OooO0o:I

    const/16 v1, 0x15

    if-lt v0, v1, :cond_0

    invoke-static {p1}, Llyiahf/vczjk/i7a;->OooO0O0(Llyiahf/vczjk/a27;)Llyiahf/vczjk/lt3;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/lt3;->getServiceInfo()Landroid/accessibilityservice/AccessibilityServiceInfo;

    move-result-object v0

    iget v1, v0, Landroid/accessibilityservice/AccessibilityServiceInfo;->flags:I

    or-int/lit8 v1, v1, 0x40

    iput v1, v0, Landroid/accessibilityservice/AccessibilityServiceInfo;->flags:I

    invoke-static {p1}, Llyiahf/vczjk/i7a;->OooO0O0(Llyiahf/vczjk/a27;)Llyiahf/vczjk/lt3;

    move-result-object p1

    invoke-interface {p1, v0}, Llyiahf/vczjk/lt3;->setServiceInfo(Landroid/accessibilityservice/AccessibilityServiceInfo;)V

    :cond_0
    return-void
.end method

.method public static OooO00o(Llyiahf/vczjk/a27;)Llyiahf/vczjk/i7a;
    .locals 1

    sget-object v0, Llyiahf/vczjk/i7a;->OooO0o0:Llyiahf/vczjk/i7a;

    if-nez v0, :cond_0

    new-instance v0, Llyiahf/vczjk/i7a;

    invoke-direct {v0, p0}, Llyiahf/vczjk/i7a;-><init>(Llyiahf/vczjk/a27;)V

    sput-object v0, Llyiahf/vczjk/i7a;->OooO0o0:Llyiahf/vczjk/i7a;

    :cond_0
    sget-object p0, Llyiahf/vczjk/i7a;->OooO0o0:Llyiahf/vczjk/i7a;

    return-object p0
.end method

.method public static OooO0O0(Llyiahf/vczjk/a27;)Llyiahf/vczjk/lt3;
    .locals 2

    invoke-static {}, Llyiahf/vczjk/ws7;->OooOO0O()Llyiahf/vczjk/ws7;

    move-result-object v0

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget v0, Llyiahf/vczjk/i7a;->OooO0o:I

    const/16 v1, 0x17

    if-le v0, v1, :cond_0

    iget-object p0, p0, Llyiahf/vczjk/a27;->OooOOOO:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/lt3;

    return-object p0

    :cond_0
    iget-object p0, p0, Llyiahf/vczjk/a27;->OooOOOO:Ljava/lang/Object;

    check-cast p0, Llyiahf/vczjk/lt3;

    return-object p0
.end method
