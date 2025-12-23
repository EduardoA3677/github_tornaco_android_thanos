.class public abstract Llyiahf/vczjk/g09;
.super Ljava/lang/Object;
.source "SourceFile"


# static fields
.field public static final OooO00o:Z

.field public static final OooO0O0:Llyiahf/vczjk/f09;

.field public static final OooO0OO:Llyiahf/vczjk/f09;

.field public static final OooO0Oo:Llyiahf/vczjk/a09$OooO00o;

.field public static final OooO0o:Llyiahf/vczjk/d09;

.field public static final OooO0o0:Llyiahf/vczjk/c09$OooO00o;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    const/4 v0, 0x0

    const/4 v1, 0x1

    :try_start_0
    const-string v2, "java.sql.Date"

    invoke-static {v2}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_0

    move v2, v1

    goto :goto_0

    :catch_0
    move v2, v0

    :goto_0
    sput-boolean v2, Llyiahf/vczjk/g09;->OooO00o:Z

    if-eqz v2, :cond_0

    new-instance v2, Llyiahf/vczjk/f09;

    const-class v3, Ljava/sql/Date;

    invoke-direct {v2, v0, v3}, Llyiahf/vczjk/f09;-><init>(ILjava/lang/Class;)V

    sput-object v2, Llyiahf/vczjk/g09;->OooO0O0:Llyiahf/vczjk/f09;

    new-instance v0, Llyiahf/vczjk/f09;

    const-class v2, Ljava/sql/Timestamp;

    invoke-direct {v0, v1, v2}, Llyiahf/vczjk/f09;-><init>(ILjava/lang/Class;)V

    sput-object v0, Llyiahf/vczjk/g09;->OooO0OO:Llyiahf/vczjk/f09;

    sget-object v0, Llyiahf/vczjk/a09;->OooO0O0:Llyiahf/vczjk/a09$OooO00o;

    sput-object v0, Llyiahf/vczjk/g09;->OooO0Oo:Llyiahf/vczjk/a09$OooO00o;

    sget-object v0, Llyiahf/vczjk/c09;->OooO0O0:Llyiahf/vczjk/c09$OooO00o;

    sput-object v0, Llyiahf/vczjk/g09;->OooO0o0:Llyiahf/vczjk/c09$OooO00o;

    sget-object v0, Llyiahf/vczjk/e09;->OooO0O0:Llyiahf/vczjk/d09;

    sput-object v0, Llyiahf/vczjk/g09;->OooO0o:Llyiahf/vczjk/d09;

    goto :goto_1

    :cond_0
    const/4 v0, 0x0

    sput-object v0, Llyiahf/vczjk/g09;->OooO0O0:Llyiahf/vczjk/f09;

    sput-object v0, Llyiahf/vczjk/g09;->OooO0OO:Llyiahf/vczjk/f09;

    sput-object v0, Llyiahf/vczjk/g09;->OooO0Oo:Llyiahf/vczjk/a09$OooO00o;

    sput-object v0, Llyiahf/vczjk/g09;->OooO0o0:Llyiahf/vczjk/c09$OooO00o;

    sput-object v0, Llyiahf/vczjk/g09;->OooO0o:Llyiahf/vczjk/d09;

    :goto_1
    return-void
.end method
