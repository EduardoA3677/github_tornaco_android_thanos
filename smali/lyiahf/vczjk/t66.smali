.class public final Llyiahf/vczjk/t66;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO0o:Llyiahf/vczjk/t66;


# instance fields
.field public final OooO00o:Llyiahf/vczjk/xa7;

.field public final OooO0O0:Ljava/lang/Class;

.field public final OooO0OO:Ljava/lang/Class;

.field public final OooO0Oo:Ljava/lang/Class;

.field public final OooO0o0:Z


# direct methods
.method static constructor <clinit>()V
    .locals 6

    new-instance v0, Llyiahf/vczjk/t66;

    sget-object v1, Llyiahf/vczjk/xa7;->OooOOO:Llyiahf/vczjk/xa7;

    const/4 v4, 0x0

    const/4 v5, 0x0

    const-class v2, Ljava/lang/Object;

    const/4 v3, 0x0

    invoke-direct/range {v0 .. v5}, Llyiahf/vczjk/t66;-><init>(Llyiahf/vczjk/xa7;Ljava/lang/Class;Ljava/lang/Class;ZLjava/lang/Class;)V

    sput-object v0, Llyiahf/vczjk/t66;->OooO0o:Llyiahf/vczjk/t66;

    return-void
.end method

.method public constructor <init>(Llyiahf/vczjk/xa7;Ljava/lang/Class;Ljava/lang/Class;ZLjava/lang/Class;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/t66;->OooO00o:Llyiahf/vczjk/xa7;

    iput-object p2, p0, Llyiahf/vczjk/t66;->OooO0Oo:Ljava/lang/Class;

    iput-object p3, p0, Llyiahf/vczjk/t66;->OooO0O0:Ljava/lang/Class;

    iput-boolean p4, p0, Llyiahf/vczjk/t66;->OooO0o0:Z

    if-nez p5, :cond_0

    const-class p5, Llyiahf/vczjk/so8;

    :cond_0
    iput-object p5, p0, Llyiahf/vczjk/t66;->OooO0OO:Ljava/lang/Class;

    return-void
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 2

    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "ObjectIdInfo: propName="

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    iget-object v1, p0, Llyiahf/vczjk/t66;->OooO00o:Llyiahf/vczjk/xa7;

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string v1, ", scope="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/t66;->OooO0Oo:Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ", generatorType="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object v1, p0, Llyiahf/vczjk/t66;->OooO0O0:Ljava/lang/Class;

    invoke-static {v1}, Llyiahf/vczjk/vy0;->OooOo0(Ljava/lang/Class;)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v1, ", alwaysAsId="

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-boolean v1, p0, Llyiahf/vczjk/t66;->OooO0o0:Z

    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
