.class public abstract Llyiahf/vczjk/g5a;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Llyiahf/vczjk/f5a;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Llyiahf/vczjk/f5a;

    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    sput-object v0, Llyiahf/vczjk/g5a;->OooO00o:Llyiahf/vczjk/f5a;

    return-void
.end method


# virtual methods
.method public OooO00o()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooO0O0()Z
    .locals 1

    const/4 v0, 0x0

    return v0
.end method

.method public OooO0OO(Llyiahf/vczjk/ko;)Llyiahf/vczjk/ko;
    .locals 1

    const-string v0, "annotations"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1
.end method

.method public abstract OooO0Oo(Llyiahf/vczjk/uk4;)Llyiahf/vczjk/z4a;
.end method

.method public OooO0o(Llyiahf/vczjk/uk4;Llyiahf/vczjk/cda;)Llyiahf/vczjk/uk4;
    .locals 1

    const-string v0, "topLevelType"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "position"

    invoke-static {p2, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-object p1
.end method

.method public OooO0o0()Z
    .locals 1

    instance-of v0, p0, Llyiahf/vczjk/f5a;

    return v0
.end method
