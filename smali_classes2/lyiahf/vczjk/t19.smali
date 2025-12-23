.class public abstract Llyiahf/vczjk/t19;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/on7;

.field public static final OooO0O0:Llyiahf/vczjk/on7;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/on7;

    const-string v1, "\\bcmp=([^\\s/]+)/"

    invoke-direct {v0, v1}, Llyiahf/vczjk/on7;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/t19;->OooO00o:Llyiahf/vczjk/on7;

    new-instance v0, Llyiahf/vczjk/on7;

    const-string v1, "\\bSTART u(\\d+)\\b"

    invoke-direct {v0, v1}, Llyiahf/vczjk/on7;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/t19;->OooO0O0:Llyiahf/vczjk/on7;

    return-void
.end method
