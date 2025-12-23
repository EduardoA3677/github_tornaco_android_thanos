.class public abstract Llyiahf/vczjk/qt9;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/mc5;

.field public final OooO0O0:Llyiahf/vczjk/mc5;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/mc5;Llyiahf/vczjk/mc5;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    if-eqz p1, :cond_0

    if-eqz p2, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/qt9;->OooO00o:Llyiahf/vczjk/mc5;

    iput-object p2, p0, Llyiahf/vczjk/qt9;->OooO0O0:Llyiahf/vczjk/mc5;

    return-void

    :cond_0
    new-instance p1, Llyiahf/vczjk/mta;

    const-string p2, "Token requires marks."

    invoke-direct {p1, p2}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    throw p1
.end method


# virtual methods
.method public abstract OooO00o()Llyiahf/vczjk/nt9;
.end method
