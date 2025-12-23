.class public abstract Llyiahf/vczjk/xt5;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/on7;

.field public static final OooO0O0:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/on7;

    const-string v1, "[^\\p{L}\\p{Digit}]"

    invoke-direct {v0, v1}, Llyiahf/vczjk/on7;-><init>(Ljava/lang/String;)V

    sput-object v0, Llyiahf/vczjk/xt5;->OooO00o:Llyiahf/vczjk/on7;

    const-string v0, "$context_receiver"

    sput-object v0, Llyiahf/vczjk/xt5;->OooO0O0:Ljava/lang/String;

    return-void
.end method
