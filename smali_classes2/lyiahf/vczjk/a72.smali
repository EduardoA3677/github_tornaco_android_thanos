.class public final Llyiahf/vczjk/a72;
.super Llyiahf/vczjk/c72;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/a72;

.field public static final OooO0O0:I


# direct methods
.method static constructor <clinit>()V
    .locals 3

    new-instance v0, Llyiahf/vczjk/a72;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/a72;->OooO00o:Llyiahf/vczjk/a72;

    sget-object v0, Llyiahf/vczjk/e72;->OooO0OO:Llyiahf/vczjk/sp3;

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget v1, Llyiahf/vczjk/e72;->OooOO0O:I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget v2, Llyiahf/vczjk/e72;->OooO:I

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    sget v0, Llyiahf/vczjk/e72;->OooOO0:I

    or-int/2addr v0, v2

    not-int v0, v0

    and-int/2addr v0, v1

    sput v0, Llyiahf/vczjk/a72;->OooO0O0:I

    return-void
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    sget v0, Llyiahf/vczjk/a72;->OooO0O0:I

    return v0
.end method
