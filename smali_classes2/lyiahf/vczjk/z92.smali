.class public final Llyiahf/vczjk/z92;
.super Ljava/lang/RuntimeException;
.source "SourceFile"


# instance fields
.field public final transient OooOOO0:Llyiahf/vczjk/or1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/or1;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/z92;->OooOOO0:Llyiahf/vczjk/or1;

    return-void
.end method


# virtual methods
.method public final fillInStackTrace()Ljava/lang/Throwable;
    .locals 1

    const/4 v0, 0x0

    new-array v0, v0, [Ljava/lang/StackTraceElement;

    invoke-virtual {p0, v0}, Ljava/lang/Throwable;->setStackTrace([Ljava/lang/StackTraceElement;)V

    return-object p0
.end method

.method public final getLocalizedMessage()Ljava/lang/String;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/z92;->OooOOO0:Llyiahf/vczjk/or1;

    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
