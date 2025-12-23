.class public final Llyiahf/vczjk/q1;
.super Llyiahf/vczjk/r02;
.source "SourceFile"


# instance fields
.field public final OooOOO:[Llyiahf/vczjk/r02;


# direct methods
.method public varargs constructor <init>([Llyiahf/vczjk/r02;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/q1;->OooOOO:[Llyiahf/vczjk/r02;

    return-void
.end method


# virtual methods
.method public final Oooo00o(ILjava/io/StringWriter;Ljava/lang/String;)I
    .locals 4

    iget-object v0, p0, Llyiahf/vczjk/q1;->OooOOO:[Llyiahf/vczjk/r02;

    const/4 v1, 0x0

    move v2, v1

    :goto_0
    const/4 v3, 0x6

    if-ge v2, v3, :cond_1

    aget-object v3, v0, v2

    invoke-virtual {v3, p1, p2, p3}, Llyiahf/vczjk/r02;->Oooo00o(ILjava/io/StringWriter;Ljava/lang/String;)I

    move-result v3

    if-eqz v3, :cond_0

    return v3

    :cond_0
    add-int/lit8 v2, v2, 0x1

    goto :goto_0

    :cond_1
    return v1
.end method
