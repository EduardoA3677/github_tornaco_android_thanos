.class public abstract Llyiahf/vczjk/tla;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/fk7;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    new-instance v0, Llyiahf/vczjk/fk7;

    sget-object v1, Llyiahf/vczjk/ula;->OooO00o:Llyiahf/vczjk/vla;

    invoke-interface {v1}, Llyiahf/vczjk/vla;->getWebkitToCompatConverter()Lorg/chromium/support_lib_boundary/WebkitToCompatConverterBoundaryInterface;

    move-result-object v1

    invoke-direct {v0, v1}, Llyiahf/vczjk/fk7;-><init>(Ljava/lang/Object;)V

    sput-object v0, Llyiahf/vczjk/tla;->OooO00o:Llyiahf/vczjk/fk7;

    return-void
.end method
