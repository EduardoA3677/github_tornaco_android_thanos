.class public final Llyiahf/vczjk/cl;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO:Ljava/lang/ThreadLocal;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/ao8;

.field public final OooO0O0:Ljava/util/ArrayList;

.field public final OooO0OO:Llyiahf/vczjk/tqa;

.field public final OooO0Oo:Llyiahf/vczjk/oO0O00o0;

.field public OooO0o:Z

.field public final OooO0o0:Llyiahf/vczjk/a27;

.field public OooO0oO:F

.field public OooO0oo:Llyiahf/vczjk/n62;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Ljava/lang/ThreadLocal;

    invoke-direct {v0}, Ljava/lang/ThreadLocal;-><init>()V

    sput-object v0, Llyiahf/vczjk/cl;->OooO:Ljava/lang/ThreadLocal;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/a27;)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    new-instance v0, Llyiahf/vczjk/ao8;

    const/4 v1, 0x0

    invoke-direct {v0, v1}, Llyiahf/vczjk/ao8;-><init>(I)V

    iput-object v0, p0, Llyiahf/vczjk/cl;->OooO00o:Llyiahf/vczjk/ao8;

    new-instance v0, Ljava/util/ArrayList;

    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    iput-object v0, p0, Llyiahf/vczjk/cl;->OooO0O0:Ljava/util/ArrayList;

    new-instance v0, Llyiahf/vczjk/tqa;

    const/4 v2, 0x4

    invoke-direct {v0, p0, v2}, Llyiahf/vczjk/tqa;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Llyiahf/vczjk/cl;->OooO0OO:Llyiahf/vczjk/tqa;

    new-instance v0, Llyiahf/vczjk/oO0O00o0;

    const/16 v2, 0xa

    invoke-direct {v0, p0, v2}, Llyiahf/vczjk/oO0O00o0;-><init>(Ljava/lang/Object;I)V

    iput-object v0, p0, Llyiahf/vczjk/cl;->OooO0Oo:Llyiahf/vczjk/oO0O00o0;

    iput-boolean v1, p0, Llyiahf/vczjk/cl;->OooO0o:Z

    const/high16 v0, 0x3f800000    # 1.0f

    iput v0, p0, Llyiahf/vczjk/cl;->OooO0oO:F

    iput-object p1, p0, Llyiahf/vczjk/cl;->OooO0o0:Llyiahf/vczjk/a27;

    return-void
.end method
