.class public abstract Llyiahf/vczjk/fu3;
.super Llyiahf/vczjk/gx3;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/au1;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/au1;)V
    .locals 1

    invoke-direct {p0}, Llyiahf/vczjk/gx3;-><init>()V

    if-eqz p1, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/fu3;->OooOOO:Llyiahf/vczjk/au1;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/NullPointerException;

    const-string v0, "type == null"

    invoke-direct {p1, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
