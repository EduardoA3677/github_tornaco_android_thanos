.class public final Llyiahf/vczjk/mn7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/io/Serializable;


# static fields
.field private static final serialVersionUID:J


# instance fields
.field private final flags:I

.field private final pattern:Ljava/lang/String;


# direct methods
.method public constructor <init>(Ljava/lang/String;I)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/mn7;->pattern:Ljava/lang/String;

    iput p2, p0, Llyiahf/vczjk/mn7;->flags:I

    return-void
.end method

.method private final readResolve()Ljava/lang/Object;
    .locals 3

    new-instance v0, Llyiahf/vczjk/on7;

    iget-object v1, p0, Llyiahf/vczjk/mn7;->pattern:Ljava/lang/String;

    iget v2, p0, Llyiahf/vczjk/mn7;->flags:I

    invoke-static {v1, v2}, Ljava/util/regex/Pattern;->compile(Ljava/lang/String;I)Ljava/util/regex/Pattern;

    move-result-object v1

    const-string v2, "compile(...)"

    invoke-static {v1, v2}, Llyiahf/vczjk/v34;->OooOoO0(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {v0, v1}, Llyiahf/vczjk/on7;-><init>(Ljava/util/regex/Pattern;)V

    return-object v0
.end method
