.class public final Llyiahf/vczjk/ypa;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/le3;


# instance fields
.field final synthetic $flowArray:[Llyiahf/vczjk/f43;


# direct methods
.method public constructor <init>([Llyiahf/vczjk/f43;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/ypa;->$flowArray:[Llyiahf/vczjk/f43;

    const/4 p1, 0x0

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO00o()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ypa;->$flowArray:[Llyiahf/vczjk/f43;

    array-length v0, v0

    new-array v0, v0, [Llyiahf/vczjk/al1;

    return-object v0
.end method
